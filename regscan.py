#-*- coding: utf-8 -*-
"""
@Author : SeonHo Lee (IT4211)
@E-mail : rhdqor100@live.co.kr
@Description : Volatility plug-in that scans the registry from the memory dump to find malware.
"""
import volatility.obj as obj
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands
import volatility.plugins.common as common
import volatility.plugins.registry.hivelist as hivelist
import volatility.plugins.registry.printkey as printkey
import volatility.plugins.registry.registryapi as registryapi
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Bytes

def vol(k):
    return bool(k.obj_offset & 0x80000000)

class RegScan(printkey.PrintKey):

    def __init__(self, config, *args, **kwargs):
        hivelist.HiveList.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'Hive offset (virtual)', type = 'int')
        config.add_option('KEY', short_option = 'K',
                          help = 'Registry Key', type = 'str')

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)
        hiveset = set()

        if not self._config.HIVE_OFFSET:
            hive_offsets = [h.obj_offset for h in hivelist.HiveList.calculate(self)]
        else:
            hive_offsets = [self._config.HIVE_OFFSET]

        for hoff in set(hive_offsets):
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            name = obj.Object("_CMHIVE", vm=addr_space, offset=hoff).get_name()
            print "[debug]", name
            root = rawreg.get_root(h)
            hive = name.split("\\")[-1]
            hiveset.add(hive)

        print hiveset
        for hive in hiveset:
            print "\n========================", hive

            for regtime, keyname in regapi.reg_get_last_modified(hive, count = 5):
                print "\n", regtime, keyname
                regapi.set_current(hive_name=hive)
                k = keyname.split('\\')[1:]
                k = '\\'.join(k)
                print k + "\n"
                for value, tp, data in self.reg_yield_values_type(regapi, hive_name = hive, key = k):
                    yield value, tp, data

            regapi.reset_current()

    def reg_yield_values_type(self, regapi, hive_name, key, thetype = None, given_root = None, raw = False):

        if key or given_root:
            h = given_root if given_root != None else regapi.reg_get_key(hive_name, key)
            if h != None:
                for v in rawreg.values(h):
                    tp, dat = rawreg.value_data(v)
                    if thetype == None or tp == thetype:
                        if raw:
                            yield v, tp, dat
                        else:
                            yield v.Name, tp, dat

        #keylist = [k for k in printkey.PrintKey.calculate(self)]
        #for n, rk in keylist:
        #    print "[+]", n, rk.Name
        #s    self.search_key(rk, "")


    def search_key(self, key, prefix):
        prefix += '\t'
        for subkey in rawreg.subkeys(key):

            if not rawreg.values(subkey):
                if not rawreg.subkeys(subkey):
                    print "[-]", subkey.Name
                    continue
                else:
                    pass

            if subkey.Name == None:
                pass
            else:
                print prefix, subkey.Name
                self.search_key(subkey, prefix)

            """
            for v in rawreg.values(subkey):
                tp, dat = rawreg.value_data(v)
                if tp == 'REG_BINARY':
                    print dat
            """

    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"

    def render_text(self, outfd, data):

        for v, tp, dat in data:
            if tp == 'REG_BINARY' or tp == 'REG_NONE':
                dat = "\n" + "\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(dat)])
            if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                dat = dat.encode("ascii", 'backslashreplace')
            if tp == 'REG_MULTI_SZ':
                for i in range(len(dat)):
                    dat[i] = dat[i].encode("ascii", 'backslashreplace')
            outfd.write("{0:13} {1:15} : {2} \n".format(tp, v, dat))

        """
        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False
        for reg, key in data:
            if key:
                keyfound = True
                outfd.write("----------------------------\n")
                outfd.write("Registry: {0}\n".format(reg))
                outfd.write("Key name: {0} {1:3s}\n".format(key.Name, self.voltext(key)))
                outfd.write("Last updated: {0}\n".format(key.LastWriteTime))
                outfd.write("\n")
                outfd.write("Subkeys:\n")
                for s in rawreg.subkeys(key):
                    if s.Name == None:
                        outfd.write("  Unknown subkey: " + s.Name.reason + "\n")
                    else:
                        outfd.write("  {1:3s} {0}\n".format(s.Name, self.voltext(s)))
                outfd.write("\n")
                outfd.write("Values:\n")
                for v in rawreg.values(key):
                    tp, dat = rawreg.value_data(v)
                    if tp == 'REG_BINARY' or tp == 'REG_NONE':
                        dat = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(dat)])
                    if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                        dat = dat.encode("ascii", 'backslashreplace')
                    if tp == 'REG_MULTI_SZ':
                        for i in range(len(dat)):
                            dat[i] = dat[i].encode("ascii", 'backslashreplace')
                    outfd.write("{0:13} {1:15} : {3:3s} {2}\n".format(tp, v.Name, dat, self.voltext(v)))
        if not keyfound:
            outfd.write("The requested key could not be found in the hive(s) searched\n")
        """
"""
    def unified_output(self, data):
        return TreeGrid([("Registry", str),
                       ("KeyName", str),
                       ("KeyStability", str),
                       ("LastWrite", str),
                       ("Subkeys", str),
                       ("SubkeyStability", str),
                       ("ValType", str),
                       ("ValName", str),
                       ("ValStability", str),
                       ("ValData", str)],
                        self.generator(data))

    def generator(self, data):
        for reg, key in data:
            if key:
                subkeys = list(rawreg.subkeys(key))
                values = list(rawreg.values(key))
                yield (0, [str("{0}".format(reg)),
                        str("{0}".format(key.Name)),
                        str("{0:3s}".format(self.voltext(key))),
                        str("{0}".format(key.LastWriteTime)),
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-"])

                if subkeys:
                    for s in subkeys:
                        if s.Name == None:
                            yield (0, [str("{0}".format(reg)),
                                str("{0}".format(key.Name)),
                                str("{0:3s}".format(self.voltext(key))),
                                str("{0}".format(key.LastWriteTime)),
                                str("Unknown subkey: {0}".format(s.Name.reason)),
                                "-",
                                "-",
                                "-",
                                "-",
                                "-"])
                        else:
                            yield (0, [str("{0}".format(reg)),
                                str("{0}".format(key.Name)),
                                str("{0:3s}".format(self.voltext(key))),
                                str("{0}".format(key.LastWriteTime)),
                                str("{0}".format(s.Name)),
                                str("{0:3s}".format(self.voltext(s))),
                                "-",
                                "-",
                                "-",
                                "-"])

                if values:
                    for v in values:
                        tp, dat = rawreg.value_data(v)
                        if tp == 'REG_BINARY' or tp == 'REG_NONE':
                            dat = Bytes(dat)
                        if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                            dat = dat.encode("ascii", 'backslashreplace')
                        if tp == 'REG_MULTI_SZ':
                            for i in range(len(dat)):
                                dat[i] = dat[i].encode("ascii", 'backslashreplace')
                        yield (0, [str("{0}".format(reg)),
                            str("{0}".format(key.Name)),
                            str("{0:3s}".format(self.voltext(key))),
                            str("{0}".format(key.LastWriteTime)),
                            "-",
                            "-",
                            str(tp),
                            str("{0}".format(v.Name)),
                            str("{0:3s}".format(self.voltext(v))),
                            str(dat)])
"""
