# regscan
Scan the registry from the memory dump to find malware.

#### Running the Plugin

Copy the plugin to volatility/plugins directory

```sh
$ python vol.py -f infected.vmem --profile=Win7SP1x86 regscan
```

#### Other Options

Scan for specific registry keys

```sh
$ python vol.py -f infected.vmem --profile=Win7SP1x86 regscan -k %REGKEY%
```

#### reference

- volatility registry api : https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Registry-Api
- plugin 제작 : http://www.dailysecu.com/news/articleView.html?idxno=5128
- 메모리 레지스트리 분석 : http://moyix.blogspot.kr/2008/02/enumerating-registry-hives.html
- plugin man page : https://fossies.org/dox/volatility-2.6/zeusscan_8py_source.html
