#-*- coding: utf-8 -*-
# Author : SeonHo Lee (IT4211)
# Email : rhdqor100@live.co.kr
# Description : Volatility plug-in that scans the registry from the memory dump to find malware.

import volatility.plugins.registry.registryapi as registryapi
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.debug as debug

#----------------------+
# RegScan Plugin class |
#----------------------+

class RegScan(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        #config.add_option('')

    def calculate(self):
        addr_space = utils.load_as(self._config, astype='physical')
        self.regapi = registryapi.RegistryApi(self._config)


    def render_text(self, outfd, data):

