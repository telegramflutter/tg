part of '../tg.dart';

class Client extends t.Client {
  Client({
    required this.socket,
    required this.obfuscation,
    required this.authorizationKey,
    required this.idGenerator,
  }) {
    _transformer = _EncryptedTransformer(
      socket.receiver,
      obfuscation,
      authorizationKey,
    );

    _transformer.stream.listen((v) {
      _handleIncomingMessage(v);
    });
  }

  static Future<AuthorizationKey> authorize(
    SocketAbstraction socket,
    Obfuscation obfuscation,
    MessageIdGenerator idGenerator,
  ) async {
    final Set<int> msgsToAck = {};

    final uot = _UnEncryptedTransformer(
      socket.receiver,
      msgsToAck,
      obfuscation,
    );

    final dh = _DiffieHellman(
      socket,
      uot.stream,
      obfuscation,
      idGenerator,
      msgsToAck,
    );
    final ak = await dh.exchange();

    await uot.dispose();
    return ak;
  }

  final AuthorizationKey authorizationKey;
  final Obfuscation obfuscation;
  final SocketAbstraction socket;
  final MessageIdGenerator idGenerator;

  late final _EncryptedTransformer _transformer;

  final Map<int, Completer<t.Result>> _pending = {};

  final _streamController = StreamController<UpdatesBase>.broadcast();

  Stream<UpdatesBase> get stream => _streamController.stream;

  void _handleIncomingMessage(TlObject msg) {
    if (msg is UpdatesBase) {
      _streamController.add(msg);
    }

    //
    if (msg is MsgContainer) {
      for (final message in msg.messages) {
        _handleIncomingMessage(message);
      }

      return;
    } else if (msg is Msg) {
      _handleIncomingMessage(msg.body);
      return;
    } else if (msg is BadMsgNotification) {
      final badMsgId = msg.badMsgId;
      final task = _pending[badMsgId];
      task?.completeError(BadMessageException._(msg));
      _pending.remove(badMsgId);
    } else if (msg is RpcResult) {
      final reqMsgId = msg.reqMsgId;
      final task = _pending[reqMsgId];

      final result = msg.result;

      if (result is RpcError) {
        task?.complete(t.Result.error(result));
        _pending.remove(reqMsgId);
        return;
      } else if (result is GzipPacked) {
        final gZippedData = GZipDecoder().decodeBytes(result.packedData);

        final newObj =
            BinaryReader(Uint8List.fromList(gZippedData)).readObject();

        final newRpcResult = RpcResult(reqMsgId: reqMsgId, result: newObj);
        _handleIncomingMessage(newRpcResult);
        return;
      }

      task?.complete(t.Result.ok(msg.result));
      _pending.remove(reqMsgId);
    } else if (msg is GzipPacked) {
      final gZippedData = GZipDecoder().decodeBytes(msg.packedData);
      final newObj = BinaryReader(Uint8List.fromList(gZippedData)).readObject();
      _handleIncomingMessage(newObj);
    }
  }

  @override
  Future<t.Result<t.TlObject>> invoke(t.TlMethod method) async {
    final preferEncryption = authorizationKey.id != 0;
    final msgsToAck = authorizationKey._msgsToAck;

    final completer = Completer<t.Result>();
    final m = idGenerator._next(preferEncryption);

    if (preferEncryption && msgsToAck.isNotEmpty) {
      final ack = idGenerator._next(false);
      final ackMsg = MsgsAck(msgIds: msgsToAck.toList());
      msgsToAck.clear();

      final container = MsgContainer(
        messages: [
          Msg(
            msgId: m.id,
            seqno: m.seqno,
            bytes: 0,
            body: method,
          ),
          Msg(
            msgId: ack.id,
            seqno: ack.seqno,
            bytes: 0,
            body: ackMsg,
          )
        ],
      );

      void nop(TlObject o) {
        //
      }

      nop(container);

      //return invoke(container, false);
    }

    _pending[m.id] = completer;
    final buffer = authorizationKey.id == 0
        ? _encodeNoAuth(method, m)
        : _encodeWithAuth(method, m, 10, authorizationKey);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    await socket.send(buffer);

    return completer.future;
  }
}
