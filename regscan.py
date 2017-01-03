#-*- coding: utf-8 -*-
# Author : SeonHo Lee (IT4211)
# Email : rhdqor100@live.co.kr
# Description : Volatility plug-in that scans the registry from the memory dump to find malware.

import volatility.plugins.registry.registryapi as registryapi # 레지스트리 API 사용, 메모리 덤프내 레지스트리 처리
import volatility.plugins.registry.hivelist as hivelist
import volatility.obj as obj
import volatility.plugins.common as common # 플러그인 커맨드 처리, window
import volatility.utils as utils
import volatility.constants as constants
import volatility.win32.tasks as tasks # 이건 프로세스 목록 얻어오는 용도?여서 안쓸 듯.
import volatility.debug as debug

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False

#TODO--------------------+
# Registry value parsing
#------------------------+

# 레지스트리의 value들을 전부 가져오고, key path와 value를 dict로 저장!
# RegYaraScanner로 던지면,
# 실행 코드 탐색(...)

class RegList(hivelist.HiveList):



#TODO--------------------+
# yara scan
#------------------------+

class BaseYaraScanner(object):

    overlap = 1024

    def __init__(self, address_space = None, rules = None ):
        self.rules = rules
        self.address_space = address_space

    def scan(self, offset, maxlen):
        # Start scanning from offset until maxlen:
        i = offset

        if isinstance(self.rules, list):
            rules = self.rules
        else:
            rules = [self.rules]

        while i < offset + maxlen:
            # Read some data and match it.
            to_read = min(constants.SCAN_BLOCKSIZE + self.overlap, offset + maxlen -i)
            data = self.address_space.zread(i, to_read)
            if data:
                for rule in rules:
                    for match in rule.match(data = data):
                        for moffset, _name, _value in match.strings:
                            if moffset < constants.SCAN_BLOCKSIZE:
                                yield match, moffset + i

            i += constants.SCAN_BLOCKSIZE

class RegYaraScanner(BaseYaraScanner):

    def __init__(self):
        BaseYaraScanner.__init__()

    def scan(self):
        #registry yara scan
        #for value, self.address_space in ~
            #for match in BaseYaraScanner.scan(self, ~):
                #yield match
#----------------------+
# RegScan Plugin class |
#----------------------+

class RegScan(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'Hive offset (virtual)', type ='int')
        config.add_option('KEY', short_option= 'K',
                          help= 'Registry Key', type='str')

    def calculate(self):
        # 메모리 이미지 물리 주소 영역 호출, 물리 주소 영역의 base 주소 return
        addr_space = utils.load_as(self._config, astype='physical')
        #self.regapi = registryapi.RegistryApi(self._config)

        # 하이브 오프셋 지정 여부
        if not self._config.HIVE_OFFSET:
            hive_offsets = [h.obj_offset for h in hivelist.HiveList.calculate(self)]
        else:
            hive_offsets = [self._config.HIVE_OFFSET]



    #def render_text(self, outfd, data):
        # 찾은 레지스트리 key, value, (disassembly?)