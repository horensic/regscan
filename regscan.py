#-*- coding: utf-8 -*-
# Author : SeonHo Lee (IT4211)
# Email : rhdqor100@live.co.kr
# Description : Volatility plug-in that scans the registry from the memory dump to find malware.

import volatility.plugins.registry.registryapi as registryapi # 레지스트리 API 사용, 메모리 덤프내 레지스트리 처리
import volatility.plugins.registry.hivelist as hivelist
import volatility.obj as obj
import volatility.plugins.common as common # 플러그인 커맨드 처리, window
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.debug as debug

#TODO--------------------+
# Registry value parsing |
#------------------------+



#TODO--------------------+
# yara scan              |
#------------------------+



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
