part of '../tg.dart';

class _EncryptedTransformer {
  _EncryptedTransformer(this._receiver, this._authKey, this._obfuscation) {
    _receiver.listen(_readFrame);
  }

  final _streamController = StreamController<TlObject>.broadcast();
  Stream<TlObject> get stream => _streamController.stream;

  final AuthorizationKey _authKey;
  final Stream<List<int>> _receiver;
  final Obfuscation? _obfuscation;
  final List<int> _read = [];

  void _readFrame(List<int> l) {
    _read.addAll(l);
    if (l.length < 4) {
      return;
    }

    final temp = _read.take(4).toList();

    _obfuscation?.recv.encryptDecrypt(temp, 4);

    final length =
        Uint8List.fromList(temp).buffer.asByteData().getInt32(0, Endian.little);

    if (l.length < length + 4) {
      return;
    }

    final buffer = Uint8List.fromList(_read.skip(4).take(length).toList());
    _read.removeRange(0, length + 4);

    final frame = _Frame.parse(buffer, _obfuscation, _authKey);
    final seqno = frame.seqno;

    if (seqno != null && (seqno & 1) != 0) {
      //_msgsToAck.add(frame.messageId);
    }

    final msg = frame.message;

    _streamController.add(msg);
  }
}

class _UnEncryptedTransformer {
  _UnEncryptedTransformer(this._receiver, this._obfuscation) {
    _subscription = _receiver.listen(_readFrame);
  }

  StreamSubscription<List<int>>? _subscription;

  Future<void> dispose() async {
    await _subscription?.cancel();
  }

  final _streamController = StreamController<TlObject>.broadcast();
  Stream<TlObject> get stream => _streamController.stream;

  final Stream<List<int>> _receiver;
  final Obfuscation? _obfuscation;
  final List<int> _read = [];

  void _readFrame(List<int> l) {
    _read.addAll(l);
    if (l.length < 4) {
      return;
    }

    final temp = _read.take(4).toList();

    _obfuscation?.recv.encryptDecrypt(temp, 4);

    final length =
        Uint8List.fromList(temp).buffer.asByteData().getInt32(0, Endian.little);

    if (l.length < length + 4) {
      return;
    }

    final buffer = Uint8List.fromList(_read.skip(4).take(length).toList());
    _read.removeRange(0, length + 4);

    final frame = _Frame.parse(buffer, _obfuscation, AuthorizationKey.empty());
    final seqno = frame.seqno;

    if (seqno != null && (seqno & 1) != 0) {
      //_msgsToAck.add(frame.messageId);
    }

    final msg = frame.message;

    _streamController.add(msg);
  }
}
