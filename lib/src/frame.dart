part of '../tg.dart';

class _Frame {
  const _Frame(
    this.message,
    this.messageId,
    this.authKeyId,
    this.seqno,
  );

  /// Parse from [Uint8List].
  factory _Frame.parse(
    Uint8List data,
    Obfuscation? obfuscation,
    AuthorizationKey authKey,
  ) {
    obfuscation?.recv.encryptDecrypt(data, data.length);

    final br = BinaryReader(data);

    final authKeyId = br.readInt64();

    if (authKeyId == 0) {
      final messageId = br.readInt64();
      final msgLength = br.readInt32(); // Message Length.

      final messageBuffer = br.readRawBytes(msgLength);
      final br2 = BinaryReader(messageBuffer);
      final message = br2.readObject();

      return _Frame(message, messageId, authKeyId, null);
    }

    //

    final decryptedData = _encryptDecryptMessage(
      Uint8List.fromList(data.skip(24).toList()),
      false,
      8,
      authKey.key,
      data,
      8,
    );

    final reader = BinaryReader(decryptedData);

    {
      final serverSalt = reader.readInt64(); // int64 salt
      final _ = serverSalt;
    }

    {
      final sessionId = reader.readInt64(); // int64 session_id
      final _ = sessionId;
    }

    final msgId = reader.readInt64(); // int64 message_id
    final seqno = reader.readInt32(); // int32 msg_seqno

    {
      final length = reader.readInt32(); // int32 message_data_length
      final _ = length;
    }

    final message = reader.readObject();

    /*
      if (decrypted_data.Length < 36) // header below+ctorNb
          throw new WTException($"Decrypted packet too small: {decrypted_data.Length}");
      _sha256Recv.TransformBlock(_dcSession.AuthKey, 96, 32, null, 0);
      _sha256Recv.TransformFinalBlock(decrypted_data, 0, decrypted_data.Length);
      if (!data.AsSpan(8, 16).SequenceEqual(_sha256Recv.Hash.AsSpan(8, 16)))
          throw new WTException("Mismatch between MsgKey & decrypted SHA256");
      */

    return _Frame(message, msgId, authKeyId, seqno);
  }

  final TlObject message;
  final int messageId;
  final int authKeyId;
  final int? seqno;

  Uint8List toUint8List(Obfuscation? obfuscation) {
    final messageBuffer = message.asUint8List();

    final data = <int>[
      ...(messageBuffer.length + 20).asUint32List(),
      ...authKeyId.asUint64List(),
      ...messageId.asUint64List(),
      ...messageBuffer.length.asUint32List(),
      ...messageBuffer,
    ];

    obfuscation?.send.encryptDecrypt(data, data.length);

    return Uint8List.fromList(data);
  }

  Map<String, dynamic> toJson() {
    return {
      'authKeyId': authKeyId,
      'messageId': messageId,
      'message': message.runtimeType.toString(),
    };
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}
