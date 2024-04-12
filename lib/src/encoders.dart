part of '../tg.dart';

Uint8List _encodeNoAuth(
  TlObject message,
  _IdSeq m,
) {
  final messageBuffer = message.asUint8List();
  final buffer = <int>[
    ...(messageBuffer.length + 20).asUint32List(),
    ...0.asUint64List(),
    ...m.id.asUint64List(),
    ...messageBuffer.length.asUint32List(),
    ...messageBuffer,
  ];

  return Uint8List.fromList(buffer);
}

Uint8List _encodeWithAuth(
  TlObject message,
  _IdSeq m,
  int sessionId,
  AuthorizationKey auth,
) {
  final messageBuffer = message.asUint8List();
  final clearLength = messageBuffer.length + 32;
  final padding = ((0x7FFFFFF0 - clearLength) % 16);
  final paddingRandomized = padding + ((2 + _rng.nextInt(14)) * 16);
  final paddingData = Uint8List(paddingRandomized);
  _rng.getBytes(paddingData);

  final clear = <int>[
    ...auth.key.skip(88).take(32),
    ...auth.salt.asUint64List(),
    ...sessionId.asUint64List(),
    ...m.id.asUint64List(),
    ...m.seqno.asUint32List(),
    ...messageBuffer.length.asUint32List(),
    ...messageBuffer,
    ...paddingData,
  ];

  final msgKey = Uint8List.fromList(sha256.convert(clear).bytes);
  final encryptedData = _encryptDecryptMessage(
    Uint8List.fromList(clear.skip(32).toList()),
    true,
    0,
    auth.key,
    msgKey,
    8,
  );

  final writerLength = 8 + 16 + encryptedData.length;

  final buffer = [
    ...writerLength.asUint32List(),
    ...auth.id.asUint64List(),
    ...msgKey.skip(8).take(16),
    ...encryptedData,
  ];

  return Uint8List.fromList(buffer);
}

class _MessageIdSequenceGenerator {
  int _lastSentMessageId = 0;
  int _seqno = 0;
  int serverTicksOffset = 0;

  _IdSeq next(bool preferEncryption) {
    var msgId =
        DateTime.now().toUtc().ticks + serverTicksOffset - 621355968000000000;
    msgId = msgId * 428 +
        (msgId >> 24) *
            25110956; // approximately unixtime*2^32 and divisible by 4

    if (msgId <= _lastSentMessageId) {
      msgId = _lastSentMessageId += 4;
    } else {
      _lastSentMessageId = msgId;
    }

    final seqno = preferEncryption ? _seqno++ * 2 + 1 : _seqno * 2;

    return _IdSeq(msgId, seqno);
  }
}

class _IdSeq {
  const _IdSeq(this.id, this.seqno);
  final int id;
  final int seqno;
}
