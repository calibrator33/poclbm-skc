from detect import MACOSX
from Miner import Miner
from Queue import Empty
from hashlib import md5
from log import say_line

from struct import pack, unpack, error
from threading import Lock
from time import sleep, time
from util import uint32, Object, tokenize, \
    bytearray_to_uint32
import os
import sys
from skeinhash import skeinhashmid

PYOPENCL = False
OPENCL = False
ADL = False


try:
    import pyopencl as cl
    PYOPENCL = True
except ImportError:
    print '\nNo PyOpenCL\n'

if PYOPENCL:
    try:
        platforms = cl.get_platforms()
        if len(platforms):
            OPENCL = True
        else:
            print '\nNo OpenCL platforms\n'
    except Exception:
        print '\nNo OpenCL\n'

def is_amd(platform):
    if 'amd' in platform.name.lower() or 'advanced micro' in platform.name.lower():
        return True
    return False

def has_amd():
    for platform in cl.get_platforms():
        if is_amd(platform):
            return True
    return False

if OPENCL:
    try:
        from adl3 import ADL_Main_Control_Create, ADL_Main_Memory_Alloc, ADL_Main_Control_Destroy, \
            ADLTemperature, ADL_Overdrive5_Temperature_Get, ADL_Adapter_NumberOfAdapters_Get, \
            AdapterInfo, LPAdapterInfo, ADL_Adapter_AdapterInfo_Get, ADL_Adapter_ID_Get, \
            ADL_OK
        from ctypes import sizeof, byref, c_int, cast
        from collections import namedtuple
        if "DISPLAY" not in os.environ:
            os.environ["DISPLAY"] = ":0"
        arv = ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1)
        if arv != ADL_OK:
            print "\nCouldn't initialize ADL interface: %d.\n" % arv
        else:
            ADL = True
            adl_lock = Lock()
    except ImportError:
        if has_amd():
            print '\nWARNING: no adl3 module found (github.com/mjmvisser/adl3), temperature control is disabled\n'
    except OSError:# if no ADL is present i.e. no AMD platform
        print '\nWARNING: ADL missing (no AMD platform?), temperature control is disabled\n'
    except NameError: # Apple
        pass
else:
    print "\nNot using OpenCL\n"

def shutdown():
    if ADL:
        ADL_Main_Control_Destroy()


def initialize(options):
    if not OPENCL:
        options.no_ocl = True
        return []

    options.worksize = tokenize(options.worksize, 'worksize')
    options.frames = tokenize(options.frames, 'frames', [30])
    options.frameSleep = tokenize(options.frameSleep, 'frameSleep', cast=float)

    platforms = cl.get_platforms()

    if options.platform >= len(platforms) or (options.platform == -1 and len(platforms) > 1):
        print 'Wrong platform or more than one OpenCL platforms found, use --platform to select one of the following\n'
        for i in xrange(len(platforms)):
            print '[%d]\t%s' % (i, platforms[i].name)
        sys.exit()

    if options.platform == -1:
        options.platform = 0

    devices = platforms[options.platform].get_devices()

    if not options.device and devices:
        print '\nOpenCL devices:\n'
        for i in xrange(len(devices)):
            print '[%d]\t%s' % (i, devices[i].name)
        print '\nNo devices specified, using all GPU devices\n'

    miners = [
        OpenCLMiner(i, options)
        for i in xrange(len(devices))
        if (
            (not options.device and devices[i].type == cl.device_type.GPU) or
            (i in options.device)
        )
    ]

    for i in xrange(len(miners)):
        miners[i].worksize = options.worksize[min(i, len(options.worksize) - 1)]
        miners[i].frames = options.frames[min(i, len(options.frames) - 1)]
        miners[i].frameSleep = options.frameSleep[min(i, len(options.frameSleep) - 1)]
        miners[i].cutoff_temp = options.cutoff_temp[min(i, len(options.cutoff_temp) - 1)]
        miners[i].cutoff_interval = options.cutoff_interval[min(i, len(options.cutoff_interval) - 1)]
    return miners


class OpenCLMiner(Miner):
    def __init__(self, device_index, options):
        super(OpenCLMiner, self).__init__(device_index, options)
        self.output_size = 0x100

        self.defspace = ''
        self.platform = cl.get_platforms()[options.platform]
        if self.platform.name == 'Apple':
            self.defspace = ' '
        self.device = self.platform.get_devices()[device_index]
        self.device_name = self.device.name.strip('\r\n \x00\t')
        self.gpu_amd = 0
        if self.device.type == cl.device_type.GPU and is_amd(self.device.platform):
            self.gpu_amd = 1
        self.frames = 30

        self.worksize = self.frameSleep= self.rate = self.estimated_rate = 0

        self.adapterIndex = None
        if ADL and is_amd(self.device.platform) and self.device.type == cl.device_type.GPU:
            with adl_lock:
                self.adapterIndex = self.get_adapter_info()
                if self.adapterIndex:
                    self.adapterIndex = self.adapterIndex[self.device_index].iAdapterIndex
        self.temperature = 0
        self.target6 = 0
        self.target7 = 0

    def id(self):
        return str(self.options.platform) + ':' + str(self.device_index) + ':' + self.device_name

    def nonce_generator(self, nonces):
        rv = []
        for i in xrange(0, len(nonces) - 4, 4):
            nonce = bytearray_to_uint32(nonces[i:i+4])
            if nonce:
                rv.append(nonce)
        return rv

    def mining_thread(self):
        say_line('started OpenCL miner on platform %d, device %d (%s)', (self.options.platform, self.device_index, self.device_name))

        (self.defines, rate_divisor, hashspace) = ('', 1000, 0xFFFFFFFF)
        self.defines += (' -D%sOUTPUT_SIZE=%s' % (self.defspace, str(self.output_size)))
        self.defines += (' -D%sOUTPUT_MASK=%s' % (self.defspace, str(self.output_size - 1)))
        self.defines += (' -D%sENDIAN_LITTLE=%d' % (self.defspace, self.device.endian_little))
        self.defines += (' -D%sGPU_AMD=%d' % (self.defspace, self.gpu_amd))
        self.defines += (' -I%s%s' % (self.defspace, os.getcwd()))

        say_line("Compiler defines: %s", self.defines)

        self.load_kernel()
        frame = 1.0 / max(self.frames, 3)
        unit = self.worksize * 256
        global_threads = unit * 10

        queue = cl.CommandQueue(self.context)

        last_rated_pace = last_rated = last_n_time = last_temperature = time()
        base = last_hash_rate = threads_run_pace = threads_run = 0
        output = bytearray((self.output_size + 1) * 4)
        output_buffer = cl.Buffer(self.context, cl.mem_flags.WRITE_ONLY | cl.mem_flags.USE_HOST_PTR, hostbuf=output)
        self.kernel.set_arg(12, output_buffer)

        work = None
        temperature = 0
        while True:
            if self.should_stop: return

            sleep(self.frameSleep)

            if (not work) or (not self.work_queue.empty()):
                try:
                    work = self.work_queue.get(True, 1)
                except Empty: continue
                else:
                    if not work: continue

                    nonces_left = hashspace

                    self.queue_kernel_parameters(work)

            if temperature < self.cutoff_temp:
                self.kernel.set_arg(11, pack('<I', base))
                cl.enqueue_nd_range_kernel(queue, self.kernel, (global_threads,), (self.worksize,))

                nonces_left -= global_threads
                threads_run_pace += global_threads
                threads_run += global_threads
                base = uint32(base + global_threads)
            else:
                threads_run_pace = 0
                last_rated_pace = time()
                sleep(self.cutoff_interval)

            now = time()
            if self.adapterIndex is not None:
                t = now - last_temperature
                if temperature >= self.cutoff_temp or t > 1:
                    last_temperature = now
                    with adl_lock:
                        self.temperature = self.get_temperature()
                        temperature = self.temperature

            t = now - last_rated_pace
            if t > 1:
                rate = (threads_run_pace / t) / rate_divisor
                last_rated_pace = now; threads_run_pace = 0
                r = last_hash_rate / rate
                if r < 0.9 or r > 1.1:
                    global_threads = max(unit * int((rate * frame * rate_divisor) / unit), unit)
                    last_hash_rate = rate

            t = now - last_rated
            if t > self.options.rate:
                self.update_rate(now, threads_run, t, work.targetQ, rate_divisor)
                last_rated = now; threads_run = 0

            queue.finish()
            cl.enqueue_read_buffer(queue, output_buffer, output)
            queue.finish()

            if output[-1]:
                result = Object()
                result.header = work.header
                result.headerX = work.headerX
                result.merkle_end = work.merkle_end
                result.time = work.time
                result.difficulty = work.difficulty
                result.target = work.target
                result.dataX = work.dataX[:]
                result.nonces = output[:]
                result.job_id = work.job_id
                result.extranonce2 = work.extranonce2
                result.server = work.server
                result.miner = self
                self.switch.put(result)
                output[:] = b'\x00' * len(output)
                cl.enqueue_write_buffer(queue, output_buffer, output)

                for miner in self.switch.miners:
                    miner.update = True

            if not self.switch.update_time:
                if nonces_left < 6 * global_threads * self.frames:
                    self.update = True
                    nonces_left += 0xFFFFFFFFFFFF
                elif 0xFFFFFFFFFFF < nonces_left < 0xFFFFFFFFFFFF:
                    say_line('warning: job finished, %s is idle', self.id())
                    work = None
            elif now - last_n_time > 1:
                last_n_time = now
                self.update_time_counter += 1
                if self.update_time_counter >= self.switch.max_update_time:
                    self.update = True
                    self.update_time_counter = 1

    def load_kernel(self):
        self.context = cl.Context([self.device], None, None)
        if self.device.extensions.find('cl_amd_media_ops') != -1:
            self.defines += ' -DBITALIGN'
            if self.device_name in ['Cedar',
                                    'Redwood',
                                    'Juniper',
                                    'Cypress',
                                    'Hemlock',
                                    'Caicos',
                                    'Turks',
                                    'Barts',
                                    'Cayman',
                                    'Antilles',
                                    'Wrestler',
                                    'Zacate',
                                    'WinterPark',
                                    'BeaverCreek']:
                self.defines += ' -DBFI_INT'

        kernel_file = open('skein.cl', 'r')
        kernel = kernel_file.read()
        kernel_file.close()
        m = md5(); m.update(''.join([self.device.platform.name, self.device.platform.version, self.device.name, self.defines, kernel]))
        cache_name = '%s.elf' % m.hexdigest()
        binary = None
        
        compile = False
        
        try:
            binary = open(cache_name, 'rb')
            self.program = cl.Program(self.context, [self.device], [binary.read()]).build(self.defines)
            say_line("Loaded existing compiled kernel: %s", cache_name)
        except (IOError, cl.LogicError) as e:
            say_line("Error loading compiled kernel: %s", cache_name)
            say_line("Recompiling kernel ...")
            compile = True
        finally:
            if binary: binary.close()
            
        if compile:
            self.program = cl.Program(self.context, kernel).build(self.defines)
            if self.defines.find('-DBFI_INT') != -1:
                patchedBinary = self.patch(self.program.binaries[0])
                self.program = cl.Program(self.context, [self.device], [patchedBinary]).build(self.defines)
            binaryW = open(cache_name, 'wb')
            binaryW.write(self.program.binaries[0])
            binaryW.close()
            say_line("Compiled kernel: %s", cache_name)

        self.kernel = self.program.search

        if not self.worksize:
            self.worksize = self.kernel.get_work_group_info(cl.kernel_work_group_info.WORK_GROUP_SIZE, self.device)
            say_line("Worksize: %d" % self.worksize)

    def queue_kernel_parameters(self, work):
        state = skeinhashmid(pack('>16I', *work.dataX[:16]))
        
        for i in xrange(8):
            self.kernel.set_arg(i, state[i * 8:i * 8 + 8])
            
        for i in range(16, 19):
            self.kernel.set_arg(i - 8, pack('>I', work.dataX[i]))
            
        if work.target[6] != self.target6 or work.target[7] != self.target7:
            say_line("Calling with tgt %.8x %.8x", (work.target[6], work.target[7]))
            self.target6 = work.target[6]
            self.target7 = work.target[7]

    def get_temperature(self):
        temperature = ADLTemperature()
        temperature.iSize = sizeof(temperature)

        if ADL_Overdrive5_Temperature_Get(self.adapterIndex, 0, byref(temperature)) == ADL_OK:
            return temperature.iTemperature/1000.0
        return 0

    def get_adapter_info(self):
        adapter_info = []
        num_adapters = c_int(-1)
        if ADL_Adapter_NumberOfAdapters_Get(byref(num_adapters)) != ADL_OK:
            say_line("ADL_Adapter_NumberOfAdapters_Get failed, cutoff temperature disabled for %s", self.id())
            return

        AdapterInfoArray = (AdapterInfo * num_adapters.value)()

        if ADL_Adapter_AdapterInfo_Get(cast(AdapterInfoArray, LPAdapterInfo), sizeof(AdapterInfoArray)) != ADL_OK:
            say_line("ADL_Adapter_AdapterInfo_Get failed, cutoff temperature disabled for %s", self.id())
            return

        deviceAdapter = namedtuple('DeviceAdapter', ['AdapterIndex', 'AdapterID', 'BusNumber', 'UDID'])
        devices = []

        for adapter in AdapterInfoArray:
            index = adapter.iAdapterIndex
            busNum = adapter.iBusNumber
            udid = adapter.strUDID

            adapterID = c_int(-1)

            if ADL_Adapter_ID_Get(index, byref(adapterID)) != ADL_OK:
                say_line("ADL_Adapter_ID_Get failed, cutoff temperature disabled for %s", self.id())
                return

            found = False
            for device in devices:
                if (device.AdapterID.value == adapterID.value):
                    found = True
                    break

            if (found == False):
                devices.append(deviceAdapter(index, adapterID, busNum, udid))

        for device in devices:
            adapter_info.append(AdapterInfoArray[device.AdapterIndex])

        return adapter_info

    def patch(self, data):
        pos = data.find('\x7fELF', 1)
        if pos != -1 and data.find('\x7fELF', pos+1) == -1:
            data2 = data[pos:]
            try:
                (id, a, b, c, d, e, f, offset, g, h, i, j, entrySize, count, index) = unpack('QQHHIIIIIHHHHHH', data2[:52])
                if id == 0x64010101464c457f and offset != 0:
                    (a, b, c, d, nameTableOffset, size, e, f, g, h) = unpack('IIIIIIIIII', data2[offset+index * entrySize : offset+(index+1) * entrySize])
                    header = data2[offset : offset+count * entrySize]
                    firstText = True
                    for i in xrange(count):
                        entry = header[i * entrySize : (i+1) * entrySize]
                        (nameIndex, a, b, c, offset, size, d, e, f, g) = unpack('IIIIIIIIII', entry)
                        nameOffset = nameTableOffset + nameIndex
                        name = data2[nameOffset : data2.find('\x00', nameOffset)]
                        if name == '.text':
                            if firstText: firstText = False
                            else:
                                data2 = data2[offset : offset + size]
                                patched = ''
                                for i in xrange(len(data2) / 8):
                                    instruction, = unpack('Q', data2[i * 8 : i * 8 + 8])
                                    if (instruction&0x9003f00002001000) == 0x0001a00000000000:
                                        instruction ^= (0x0001a00000000000 ^ 0x0000c00000000000)
                                    patched += pack('Q', instruction)
                                return ''.join([data[:pos+offset], patched, data[pos + offset + size:]])
            except error:
                pass
        return data
