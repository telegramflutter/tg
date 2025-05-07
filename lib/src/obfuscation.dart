part of '../tg.dart';

/// Obfuscation.
class Obfuscation {
  const Obfuscation._(this.send, this.recv, this.preamble);

  /// Generate a random obfuscator.
  factory Obfuscation.random(bool padded, int dcId, [Uint8List? secret]) {
    final random = Uint8List(58);

    do {
      _rng.getBytes(random, 0, 58);
    } while (false);

// TODO (xclud):
    // while (preamble[0] == 0xef ||
    // 	BinaryPrimitives.ReadUInt32LittleEndian(preamble) is 0x44414548 or 0x54534f50 or 0x20544547 or 0x4954504f or 0x02010316 or 0xdddddddd or 0xeeeeeeee ||
    // 	BinaryPrimitives.ReadInt32LittleEndian(preamble.AsSpan(4)) == 0);

    return Obfuscation.preamble(random, padded, dcId);
  }

  /// Generate an obfuscator from a pre-computed preamble.
  ///
  /// [random] Must be 58 bytes random.
  factory Obfuscation.preamble(Uint8List random, bool padded, int dcId,
      [Uint8List? secret]) {
    final protocolId = padded ? 0xDD : 0xEE;
    final preamble = Uint8List(64);

    // TODO (xclud): Validate the random buffer.

    preamble.setRange(0, 58, random);

    preamble[62] = preamble[56];
    preamble[63] = preamble[57];

    preamble[56] = preamble[57] = preamble[58] = preamble[59] = protocolId;

    preamble[60] = dcId;
    preamble[61] = dcId >> 8;

    var recvKey = Uint8List.fromList(preamble.sublist(8, 40).toList());
    final recvIV = Uint8List.fromList(preamble.sublist(40, 56).toList());

    preamble.reverse(8, 48);

    var sendKey = Uint8List.fromList(preamble.sublist(8, 40).toList());
    final sendIV = Uint8List.fromList(preamble.sublist(40, 56).toList());

    final sec = secret;
    if (sec != null) {
      sendKey = Uint8List.fromList(
          sha256([...sendKey.sublist(0, 32), ...sec.sublist(0, 16)]));

      recvKey = Uint8List.fromList(
          sha256([...recvKey.sublist(0, 32), ...sec.sublist(0, 16)]));
    }

    final sendCtr = AesCtr(sendKey, sendIV);
    final recvCtr = AesCtr(recvKey, recvIV);
    final encrypted = Uint8List.fromList(preamble.toList());

    sendCtr.encryptDecrypt(encrypted, 64);

    for (int i = 56; i < 64; i++) {
      preamble[i] = encrypted[i];
    }

    return Obfuscation._(sendCtr, recvCtr, preamble);
  }

  /// Sender encryption.
  final AesCtr send;

  /// Receiver encryption.
  final AesCtr recv;

  /// Preamble used to generate [send] and [recv].
  final Uint8List preamble;
}

/// Implementation of AES-Counter algorithm.
class AesCtr {
  /// Constructor.
  AesCtr(this.key, this.iv);

  /// Key.
  final Uint8List key;

  /// IV.
  final Uint8List iv;

  final _ecount = Uint8List(16);
  int _num = 0;

  /// Transforms the input buffer.
  void encryptDecrypt(List<int> buffer, int length) {
    final encryptor = AES(Key(key), mode: AESMode.ecb);

    for (int i = 0; i < length; i++) {
      if (_num == 0) {
        final e = encryptor.encrypt(iv);

        _ecount.setAll(0, e.bytes.take(16));

        for (int n = 15; n >= 0; n--) {
          if (++iv[n] != 0) {
            break;
          }
        }
      }

      buffer[i] ^= _ecount[_num];
      _num = (_num + 1) % 16;
    }
  }
}
