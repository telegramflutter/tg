import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:example/io_socket.dart';
import 'package:t/t.dart' as t;
import 'package:tg/tg.dart' as tg;
import 'package:socks5_proxy/socks_client.dart';

const apiId = 611335;
const apiHash = 'd524b414d21f4d37f08684c1df41ac9c';

Future<tg.SocketAbstraction> _createSocket(String ip, int port) async {
  final socket = await SocksTCPClient.connect(
    [
      ProxySettings(InternetAddress.tryParse('192.168.1.13')!, 1080),
    ],
    InternetAddress(ip),
    port,
  );

  // final socket = await Socket.connect(
  //   _dc.ipAddress,
  //   _dc.port,
  // );

  return IoSocket(socket);
}

class Telegram {
  Telegram._();
  static final Telegram instance = Telegram._();

  final dcs = <t.DcOption>[] = [];
  final _logController = StreamController<Object>();

  Stream<Object> get logs => _logController.stream;

  void _log(Object text) {
    _logController.add(text);
  }

  tg.Client? _c;
  t.DcOption _dc = const t.DcOption(
    ipv6: false,
    mediaOnly: false,
    tcpoOnly: false,
    cdn: false,
    static: false,
    thisPortOnly: false,
    id: 1,
    ipAddress: '149.154.167.50',
    port: 443,
  );

  void changeDataCenter(t.DcOption dc) async {
    _c = null;
    _dc = dc;
  }

  Future<tg.Client> connect() async {
    final cc = _c;
    if (cc != null) {
      return cc;
    }
    _log('Connecting...');
    final socket = await _createSocket(_dc.ipAddress, _dc.port);

    _log('Connected.');
    final obfuscation = tg.Obfuscation.random(false, _dc.id);
    final idGenerator = tg.MessageIdGenerator();

    await socket.send(obfuscation.preamble);

    final loaded = loadSession();

    final authKey = loaded ??
        await tg.Client.authorize(
          socket,
          obfuscation,
          idGenerator,
        );

    final client = tg.Client(
      socket: socket,
      obfuscation: obfuscation,
      authorizationKey: authKey,
      idGenerator: idGenerator,
    );

    // final config = await client.help.getConfig();
    // _log('Config: $config');

    client.stream.listen((event) {
      _log(event);
    });

    final cfg = await client.initConnection<t.Config>(
      apiId: apiId,
      deviceModel: 'Galaxy S24',
      systemVersion: 'Android 14',
      appVersion: '1.0.0',
      systemLangCode: 'en',
      langPack: '',
      langCode: 'en',
      query: const t.HelpGetConfig(),
    );

    dcs.clear();
    dcs.addAll(cfg.result!.dcOptions.map((e) => e as t.DcOption));

    _log('Config: $cfg');

    _c = client;
    return client;
  }
}

tg.AuthorizationKey? loadSession() {
  try {
    final text = File('auth.json').readAsStringSync();
    final jsn = jsonDecode(text);

    return tg.AuthorizationKey.fromJson(jsn);
  } catch (e) {
    return null;
  }
}
