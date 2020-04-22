function getTemplate() {
  var tpl = {
    CLIENT: {
      log: {
        access: '',
        error: '',
        loglevel: 'error'
      },
      inbounds: [],
      outbounds: [{
          protocol: 'vmess',
          settings: {
            vnext: [{
              address: 'host.host',
              port: 1234,
              users: [{
                email: 'user@v2ray.com',
                id: '',
                alterId: 0,
                security: 'auto'
              }]
            }]
          },
          streamSettings: {
            network: 'tcp'
          },
          mux: {
            enabled: true
          },
          tag: 'proxy'
        },
        {
          protocol: 'freedom',
          tag: 'direct',
          settings: {
            domainStrategy: 'UseIP'
          }
        }
      ],
      dns: {
        servers: [
          '1.0.0.1',
          'localhost'
        ]
      },
      routing: {
        domainStrategy: 'IPIfNonMatch',
        rules: [{
            type: 'field',
            ip: [
              'geoip:private',
              'geoip:cn'
            ],
            outboundTag: 'direct'
          },
          {
            type: 'field',
            domain: [
              'geosite:cn'
            ],
            outboundTag: 'direct'
          }
        ]
      }
    },

    http: {
      header: {
        type: 'http',
        request: {
          version: '1.1',
          method: 'GET',
          path: [
            '/'
          ],
          headers: {
            Host: [
              'www.cloudflare.com',
              'www.amazon.com'
            ],
            'User-Agent': [
              'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36',
              'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.75 Safari/537.36',
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0'
            ],
            Accept: [
              'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
            ],
            'Accept-language': [
              'zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4'
            ],
            'Accept-Encoding': [
              'gzip, deflate, br'
            ],
            'Cache-Control': [
              'no-cache'
            ],
            Pragma: 'no-cache'
          }
        }
      }
    },

    kcp: {
      mtu: 1350,
      tti: 50,
      uplinkCapacity: 12,
      downlinkCapacity: 100,
      congestion: false,
      readBufferSize: 2,
      writeBufferSize: 2,
      header: {
        type: 'wechat-video'
      }
    },

    ws: {
      connectionReuse: true,
      path: '/path',
      headers: {
        Host: 'host.host.host'
      }
    },

    h2: {
      host: [
        'host.com'
      ],
      path: '/host'
    },

    quic: {
      security: 'none',
      key: '',
      header: {
        type: 'none'
      }
    },

    in_socks: {
      tag: 'socks-in',
      port: 10808,
      listen: '::',
      protocol: 'socks',
      settings: {
        auth: 'noauth',
        udp: true,
        ip: '127.0.0.1'
      }
    },

    in_http: {
      tag: 'http-in',
      port: 8123,
      listen: '::',
      protocol: 'http'
    },

    in_mt: {
      tag: 'mt-in',
      port: 6666,
      protocol: 'mtproto',
      settings: {
        users: [{
          secret: ''
        }]
      }
    },

    out_mt: {
      tag: 'mt-out',
      protocol: 'mtproto',
      proxySettings: {
        tag: 'proxy'
      }
    },

    in_dns: {
      port: 53,
      tag: 'dns-in',
      protocol: 'dokodemo-door',
      settings: {
        address: '1.1.1.1',
        port: 53,
        network: 'tcp,udp'
      }
    },

    conf_dns: {
      hosts: {
        'geosite:category-ads': '127.0.0.1',
        'domain:googleapis.cn': 'googleapis.com'
      },
      servers: [
        '1.0.0.1',
        {
          address: '1.2.4.8',
          domains: [
            'geosite:cn'
          ],
          port: 53
        }
      ]
    },

    in_tproxy: {
      tag: 'tproxy-in',
      port: 1080,
      protocol: 'dokodemo-door',
      settings: {
        network: 'tcp,udp',
        followRedirect: true
      },
      streamSettings: {
        sockopt: {
          tproxy: 'tproxy'
        }
      },
      sniffing: {
        enabled: true,
        destOverride: [
          'http',
          'tls'
        ]
      }
    },

    in_api: {
      tag: 'api',
      port: 10085,
      listen: '127.0.0.1',
      protocol: 'dokodemo-door',
      settings: {
        address: '127.0.0.1'
      }
    },

    out_ss: {
      email: 'user@ss',
      address: '',
      method: '',
      ota: false,
      password: '',
      port: 0
    }
  }
  return tpl
}

function parseSs(link) {
  var retobj = {
    v: '2',
    ps: '',
    add: '',
    port: '',
    id: '',
    aid: '',
    net: 'shadowsocks',
    type: '',
    host: '',
    path: '',
    tls: ''
  }
  // remove ss:// profix
  var info = link.substring(5)
  if (info.includes('#')) {
    var items = info.split('#')
    info = items[0]
    items.shift()
    retobj.ps = items.join('#')
  }
  if (info.includes('@')) {
    var addrport = info.substring(info.indexOf('@') + 1).split(':')
    retobj.add = addrport[0]
    retobj.port = addrport[1]

    info = info.split('@')[0]
    var blen = info.length
    if (blen % 4 > 0) {
      info += '=' * (4 - blen % 4)
    }
    info = window.atob(info)

    var metpass = info.split(':')
    retobj.aid = metpass[0]
    metpass.shift()
    retobj.id = metpass.join(':')
  } else {
    var blen = info.length
    if (blen % 4 > 0) {
      info += '=' * (4 - blen % 4)
    }
    info = window.atob(info)
    var items = info.split('@')
    var metpass = items[0].split(':')
    retobj.aid = metpass[0]
    metpass.shift()
    retobj.id = metpass.join(':')
    var addrport = items[1].split(':')
    retobj.add = addrport[0]
    retobj.port = addrport[1]
  }

  return retobj
}

function fillShadowsocks(_c, _v) {
  var _ss = getTemplate().out_ss
  _ss.email = _v.ps + '@ss'
  _ss.address = _v.add
  _ss.port = parseInt(_v.port)
  _ss.method = _v.aid
  _ss.password = _v.id

  var _outbound = _c.outbounds[0]
  _outbound.protocol = 'shadowsocks'
  _outbound.settings.servers = [_ss]

  delete _outbound.settings.vnext
  delete _outbound.streamSettings
  delete _outbound.mux

  return _c
}

function fillBasic(_c, _v) {
  var _outbound = _c.outbounds[0]
  var _vnext = _outbound.settings.vnext[0]

  _vnext.address = _v.add
  _vnext.port = parseInt(_v.port)
  _vnext.users[0].id = _v.id
  _vnext.users[0].alterId = parseInt(_v.aid)

  _outbound.streamSettings.network = _v.net

  if (_v.tls === 'tls') {
    _outbound.streamSettings.security = 'tls'
    _outbound.streamSettings.tlsSettings = {
      allowInsecure: true
    }
    if (_v.host !== '') {
      _outbound.streamSettings.tlsSettings.serverName = _v.host
    }
  }
  return _c
}

function fillTcpHttp(_c, _v) {
  var tcps = getTemplate().http
  tcps.header.type = _v.type
  if (_v.host !== '') {
    // multiple host
    tcps.header.request.headers.Host = _v.host.split(',')
  }

  if (_v.path !== '') {
    tcps.header.request.path = [_v.path]
  }

  _c.outbounds[0].streamSettings.tcpSettings = tcps
  return _c
}

function fillQuic(_c, _v) {
  var quics = getTemplate().quic
  quics.header.type = _v.type
  quics.security = _v.host
  quics.key = _v.path
  _c.outbounds[0].streamSettings.quicSettings = quics
  return _c
}

function fillH2(_c, _v) {
  var h2s = getTemplate().h2
  h2s.path = _v.path
  h2s.host = [_v.host]
  _c.outbounds[0].streamSettings.httpSettings = h2s
  return _c
}

function fillWs(_c, _v) {
  var wss = getTemplate().ws
  wss.path = _v.path
  wss.headers.Host = _v.host
  _c.outbounds[0].streamSettings.wsSettings = wss
  return _c
}

function fillKcp(_c, _v) {
  var kcps = getTemplate().kcp
  kcps.header.type = _v.type
  _c.outbounds[0].streamSettings.kcpSettings = kcps
  return _c
}

function vmess2client(_t, _v) {
  var _net = _v.net
  var _type = _v.type

  if (_net === 'shadowsocks') {
    return fillShadowsocks(_t, _v)
  } else {
    var _c = fillBasic(_t, _v)
    switch (_net) {
      case 'tcp': {
        if (_type === 'http') {
          return fillTcpHttp(_c, _v)
        }
        return _c
      }
      case 'quic': {
        return fillQuic(_c, _v)
      }
      case 'h2': {
        return fillH2(_c, _v)
      }
      case 'ws': {
        return fillWs(_c, _v)
      }
      case 'kcp': {
        return fillKcp(_c, _v)
      }
      default: {
        console.log('Unrecognised network protocol type')
        throw 'Invalid network type'
      }
    }
  }
}

function fillDns(_c) {
  var dns = {
    address: '119.29.29.29',
    port: 53,
    domains: ['geosite:cn']
  }
  _c.dns.servers.push(dns)
  _c.routing.domainStrategy = 'IPOnDemand'
  return _c
}

function fillInbounds(_c) {
  var socks = 'socks:1080'
  var _in = socks.split(':')
  var _proto = _in[0]
  var _port = _in[1]
  var _tplKey = 'in_' + _proto
  var _inobj = getTemplate()[_tplKey]
  _inobj.port = parseInt(_port)
  _c.inbounds.push(_inobj)
  return _c
}

function parseVmess(link) {
  var info = link.substring(8); // remove vmess:// profix
  var blen = info.length;
  if (blen % 4 > 0) {
    info += "=" * (4 - blen % 4);
  }
  info = window.atob(info)
  var jsonmap = JSON.parse(info);
  return jsonmap;
}

function showOutput(itemObj) {
  console.log(itemObj)
  document.getElementById('stdout').innerHTML = JSON.stringify(itemObj)
}

function main() {
  var item
  var input = document.getElementById('inp')
  if (input.value) {
    if (input.value.indexOf('ss://') === 0) {
      item = parseSs(input.value)
    } else if (input.value.indexOf('vmess://') === 0) {
      item = parseVmess(input.value)
    } else {
      document.getElementById('stdout').innerHTML = 'Unrecognised input'
      return
    }
  } else {
    document.getElementById('stdout').innerHTML = 'You entered nothing'
    return
  }

  item = vmess2client(getTemplate().CLIENT, item)
  item = fillDns(item)
  item = fillInbounds(item)
  showOutput(item)
  return
}

