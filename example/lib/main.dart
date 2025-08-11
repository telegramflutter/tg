import 'dart:io';

import 'package:example/telegram.dart';
import 'package:flutter/material.dart';
import 'package:t/t.dart' as t;
import 'package:tg/tg.dart' as tg;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String _label = 'Click Login';
  int _state = 0;
  String _phoneNumber = '';

  @override
  void initState() {
    Telegram.instance.logs.listen(logToList);
    super.initState();
  }

  t.AuthSentCode? _authSentCode;
  t.AccountPassword? _accountPassword;

  final _controller = TextEditingController();
  final _log = <String>[];

  void _login() async {
    final c = await Telegram.instance.connect();

    if (_state == 0) {
      _state++;
      setState(() {
        _label = 'Phone Number';
      });

      return;
    }

    if (_state == 1) {
      _phoneNumber = _controller.text.trim();
      _controller.clear();

      final sendCodeResponse = await c.auth.sendCode(
        apiId: apiId,
        apiHash: apiHash,
        phoneNumber: _phoneNumber,
        settings: const t.CodeSettings(
          allowFlashcall: false,
          currentNumber: true,
          allowAppHash: false,
          allowMissedCall: false,
          allowFirebase: false,
          unknownNumber: false,
        ),
      );

      logToList('Send Code: $sendCodeResponse');

      final error = sendCodeResponse.error;
      if (error != null) {
        final dcId = int.parse(error.errorMessage.split('_').last);

        final dc =
            Telegram.instance.dcs.firstWhere((x) => x.id == dcId && !x.ipv6);

        Telegram.instance.changeDataCenter(dc);

        _state = 0;
        setState(() {});
        _log.clear();

        return;
      }

      _authSentCode = sendCodeResponse.result as t.AuthSentCode;
      _label = 'Login code';

      _state++;
      setState(() {});
      return;
    }

    if (_state == 2) {
      final phoneCode = _controller.text.trim();
      _controller.clear();

      final signInResponse = await c.auth.signIn(
        phoneCodeHash: _authSentCode!.phoneCodeHash,
        phoneNumber: _phoneNumber,
        phoneCode: phoneCode,
      );

      logToList('SignIn: $signInResponse');

      if (signInResponse.error != null) {
        final accountPasswordResponse = await c.account.getPassword();
        logToList('Get Password: $accountPasswordResponse');
        _accountPassword = accountPasswordResponse.result as t.AccountPassword;

        if (_accountPassword!.hint != null) {
          _label = 'Password (Hint: ${_accountPassword!.hint})';
        } else {
          _label = 'Password';
        }

        _state++;
        setState(() {});
        return;
      }
    }
    if (_state == 3) {
      final passwordInput = _controller.text.trim();
      _controller.clear();

      final password = await tg.check2FA(_accountPassword!, passwordInput);
      final checkPasswordResponse =
          await c.auth.checkPassword(password: password);
      logToList(checkPasswordResponse);

      File('auth.json').writeAsStringSync(c.authorizationKey.toString());
    }
  }

  void logToList(Object text) {
    _log.add(text.toString());
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          TextFormField(
            controller: _controller,
            decoration: InputDecoration(labelText: _label),
          ),
          SizedBox(height: 8),
          Expanded(
              child: ListView(
            children: _log.map((e) {
              return Padding(
                padding: EdgeInsets.all(8),
                child: Text(e),
              );
            }).toList(),
          )),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _login,
        tooltip: 'Login',
        child: const Icon(Icons.login),
      ),
    );
  }
}
