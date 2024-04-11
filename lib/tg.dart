/// Telegram Client API (MTProto) to connect to Telegram and control a user programmatically.
library tg;

import 'dart:async';
import 'dart:convert';

import 'dart:math';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:t/t.dart';
import 'package:t/t.dart' as t;

part 'src/decoders.dart';
part 'src/encoders.dart';
part 'src/encryption.dart';
part 'src/exceptions.dart';
part 'src/extensions.dart';
part 'src/private.dart';
part 'src/dh.dart';
part 'src/diffie_hellman.dart';
part 'src/frame.dart';
part 'src/public_keys.dart';
part 'src/client.dart';
part 'src/constants.dart';
part 'src/obfuscation.dart';
part 'src/session.dart';
part 'src/telegram_client.dart';
