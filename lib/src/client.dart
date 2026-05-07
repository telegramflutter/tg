part of '../tg.dart';

class _PendingTask {
  final Completer<t.Result> completer;
  final t.TlMethod method;
  final List<int> sentAcks;

  _PendingTask(this.completer, this.method, this.sentAcks);
}

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
      msgsToAck,
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
    );
    final ak = await dh.exchange();

    await uot.dispose();
    return ak;
  }

  AuthorizationKey authorizationKey;
  final Obfuscation obfuscation;
  final SocketAbstraction socket;
  final MessageIdGenerator idGenerator;
  final Set<int> msgsToAck = {};

  late final _EncryptedTransformer _transformer;

  final Map<int, _PendingTask> _pendingTasks = {};

  final _streamController = StreamController<UpdatesBase>.broadcast();

  final int _sessionId = Random.secure().nextInt(0x7FFFFFFF);

  Stream<UpdatesBase> get stream => _streamController.stream;

  void _handleIncomingMessage(TlObject msg) {
    if (msg is UpdatesBase) {
      _streamController.add(msg);
    }

    if (msg is MsgContainer) {
      for (final message in msg.messages) {
        _handleIncomingMessage(message);
      }
      return;
    } else if (msg is Msg) {
      if ((msg.seqno & 1) != 0) {
        msgsToAck.add(msg.msgId);
      }
      _handleIncomingMessage(msg.body);
      return;
    } else if (msg is BadMsgNotification) {
      final badMsgId = msg.badMsgId;
      final task = _pendingTasks[badMsgId];
      task?.completer.completeError(BadMessageException._(msg));
      _pendingTasks.remove(badMsgId);
    } else if (msg is RpcResult) {
      final reqMsgId = msg.reqMsgId;
      final task = _pendingTasks[reqMsgId];

      final result = msg.result;

      if (result is RpcError) {
        task?.completer.complete(t.Result.error(result));
        _pendingTasks.remove(reqMsgId);
        return;
      } else if (result is GzipPacked) {
        final gZippedData = GZipDecoder().decodeBytes(result.packedData);

        final newObj =
            BinaryReader(Uint8List.fromList(gZippedData)).readObject();

        final newRpcResult = RpcResult(reqMsgId: reqMsgId, result: newObj);
        _handleIncomingMessage(newRpcResult);
        return;
      }
      task?.completer.complete(t.Result.ok(msg.result));
      _pendingTasks.remove(reqMsgId);
    } else if (msg is GzipPacked) {
      final gZippedData = GZipDecoder().decodeBytes(msg.packedData);
      final newObj = BinaryReader(Uint8List.fromList(gZippedData)).readObject();
      _handleIncomingMessage(newObj);
    } else if (msg is NewSessionCreated) {
      authorizationKey = AuthorizationKey(
        authorizationKey.id,
        authorizationKey.key,
        msg.serverSalt,
      );
    } else if (msg is BadServerSalt) {
      authorizationKey = AuthorizationKey(
        authorizationKey.id,
        authorizationKey.key,
        msg.newServerSalt,
      );

      final badMsgId = msg.badMsgId;
      final task = _pendingTasks.remove(badMsgId);

      if (task != null) {
        if (task.sentAcks.isNotEmpty) {
          msgsToAck.addAll(task.sentAcks);
        }
        _invoke(task.method, task.completer);
      }
    }
  }

  @override
  Future<t.Result<t.TlObject>> invoke(t.TlMethod method) {
    return _invoke(method, Completer<t.Result>());
  }

  Future<t.Result<t.TlObject>> _invoke(
    t.TlMethod method,
    Completer<t.Result> completer,
  ) async {
    final preferEncryption = authorizationKey.id != 0;

    final m = idGenerator._next(preferEncryption);
    List<int> currentAcks = [];

    if (preferEncryption && msgsToAck.isNotEmpty) {
      currentAcks = msgsToAck.toList();
      final ack = idGenerator._next(false);
      final ackMsg = MsgsAck(msgIds: currentAcks);
      msgsToAck.clear();

      // final container = MsgContainer(
      //   messages: [
      //     Msg(msgId: m.id, seqno: m.seqno, bytes: 0, body: method),
      //     Msg(msgId: ack.id, seqno: ack.seqno, bytes: 0, body: ackMsg),
      //   ],
      // );

      // void nop(TlObject o) {
      //   //
      // }

      // nop(container);

      //return invoke(container, false);

      final ackBuffer = _encodeWithAuth(
        ackMsg,
        ack,
        _sessionId,
        authorizationKey,
      );
      obfuscation.send.encryptDecrypt(ackBuffer, ackBuffer.length);
      await socket.send(ackBuffer);
    }

    _pendingTasks[m.id] = _PendingTask(completer, method, currentAcks);
    final buffer = authorizationKey.id == 0
        ? _encodeNoAuth(method, m)
        : _encodeWithAuth(method, m, _sessionId, authorizationKey);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    await socket.send(buffer);

    return completer.future;
  }
}
