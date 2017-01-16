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

- http://www.dailysecu.com/news/articleView.html?idxno=5128
- http://moyix.blogspot.kr/2008/02/enumerating-registry-hives.html
-