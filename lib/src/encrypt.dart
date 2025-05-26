import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Wraps the AES Algorithm.
class AesEcb {
  final Key key;
  final BlockCipher _cipher;

  AesEcb(this.key) : _cipher = BlockCipher('AES/ECB');

  Encrypted encrypt(Uint8List bytes) {
    _cipher
      ..reset()
      ..init(true, KeyParameter(key.bytes));

    return Encrypted(_processBlocks(bytes));
  }

  Uint8List decrypt(Encrypted encrypted) {
    _cipher
      ..reset()
      ..init(false, KeyParameter(key.bytes));

    return _processBlocks(encrypted.bytes);
  }

  void encrypt2(
    Uint8List input,
    int inputOffset,
    int inputCount,
    Uint8List output,
    int outputOffset,
  ) {
    final inn = input.skip(inputOffset).take(inputCount).toList();
    final enc = encrypt(Uint8List.fromList(inn));

    output.setRange(outputOffset, outputOffset + enc.bytes.length, enc.bytes);
  }

  void decrypt2(
    Uint8List input,
    int inputOffset,
    int inputCount,
    Uint8List output,
    int outputOffset,
  ) {
    final inn = input.skip(inputOffset).take(inputCount).toList();
    final enc = decrypt(Encrypted(Uint8List.fromList(inn)));

    output.setRange(outputOffset, outputOffset + enc.length, enc);
  }

  Uint8List _processBlocks(Uint8List input) {
    var output = Uint8List(input.lengthInBytes);

    for (int offset = 0; offset < input.lengthInBytes;) {
      offset += _cipher.processBlock(input, offset, output, offset);
    }

    return output;
  }
}

/// Represents an encripted value.
class Encrypted {
  /// Creates an Encrypted object from a Uint8List.
  const Encrypted(this.bytes);

  /// Gets the Encrypted bytes.
  final Uint8List bytes;
}

/// Represents an Initialization Vector.
class IV extends Encrypted {
  /// Creates an Initialization Vector object from a Uint8List.
  IV(Uint8List bytes) : super(bytes);
}

/// Represents an Encryption Key.
class Key extends Encrypted {
  /// Creates an Encryption Key object from a Uint8List.
  Key(Uint8List bytes) : super(bytes);

  int get length => bytes.lengthInBytes;
}
