import 'dart:convert';
import 'dart:io';

import 'package:t/t.dart' as t;
import 'package:tg/tg.dart' as tg;
import 'package:socks5_proxy/socks_client.dart';

const apiId = 611335;
const apiHash = 'd524b414d21f4d37f08684c1df41ac9c';

var _dc = const t.DcOption(
  ipv6: false,
  mediaOnly: false,
  tcpoOnly: false,
  cdn: false,
  static: false,
  thisPortOnly: false,
  //id: 2,
  //ipAddress: '149.154.167.50',
  id: 4,
  ipAddress: '149.154.167.92',
  // id: 2,
  // ipAddress: '149.154.167.40',
  port: 443,
);

Future<Socket> connect() async {
  final socket = await SocksTCPClient.connect(
    [
      ProxySettings(InternetAddress.loopbackIPv4, 9909),
    ],
    InternetAddress(_dc.ipAddress),
    _dc.port,
  );

  return socket;
}

void main() async {
  print('Connecting...');
  final socket = await connect();
  final obfuscation = tg.Obfuscation.random(false, _dc.id);

  final authKey = loadAuthorizationKey() ??
      await tg.Client.authorize(socket, socket, obfuscation);

  File('session.json').writeAsStringSync(authKey.toString());
  print('Auth Key: $authKey');

  final c = tg.Client(
    receiver: socket,
    sender: socket,
    obfuscation: obfuscation,
    authorizationKey: authKey,
  );

  // c.session.listen((event) {
  //   print(event);

  //   File('session.json').writeAsStringSync(event.toString());
  // });

  c.stream.listen((event) {
    print(event);
  });

  print('Connected.');

  c.start();

  await Future.delayed(const Duration(milliseconds: 100));

  final cfg = await c.initConnection<t.Config>(
    apiId: apiId,
    deviceModel: 'Galaxy S24',
    systemVersion: 'Android 14',
    appVersion: '1.0.0',
    systemLangCode: 'en',
    langPack: '',
    langCode: 'en',
    query: const t.HelpGetConfig(),
  );

  print('Config: $cfg');

  print('Phone Number: ');
  final phoneNumber = stdin.readLineSync() ?? '';

  final sendCodeResponse = await c.auth.sendCode(
    apiId: apiId,
    apiHash: apiHash,
    phoneNumber: phoneNumber,
    settings: const t.CodeSettings(
      allowFlashcall: false,
      currentNumber: true,
      allowAppHash: false,
      allowMissedCall: false,
      allowFirebase: false,
      unknownNumber: false,
    ),
  );

  print('Send Code: $sendCodeResponse');

  final sentCodeResult = sendCodeResponse.result as t.AuthSentCode;

  stdout.write('Login code: ');
  final phoneCode = stdin.readLineSync();

  final signInResponse = await c.auth.signIn(
    phoneCodeHash: sentCodeResult.phoneCodeHash,
    phoneNumber: phoneNumber,
    phoneCode: phoneCode,
  );

  print('SignIn: $signInResponse');

  if (signInResponse.error != null) {
    final accountPasswordResponse = await c.account.getPassword();
    print('Get Password: $accountPasswordResponse');
    final accountPassword = accountPasswordResponse.result as t.AccountPassword;

    if (accountPassword.hint != null) {
      stdout.write('Password (Hint: ${accountPassword.hint}): ');
    } else {
      stdout.write('Password: ');
    }

    final passwordInput = stdin.readLineSync() ?? '';

    final password = tg.check2FA(accountPassword, passwordInput);
    final checkPasswordResponse =
        await c.auth.checkPassword(password: password);
    print(checkPasswordResponse);
  }
}

tg.AuthorizationKey? loadAuthorizationKey() {
  try {
    final text = File('session.json').readAsStringSync();
    final jsn = jsonDecode(text);

    return tg.AuthorizationKey.fromJson(jsn);
  } catch (e) {
    return null;
  }
}
