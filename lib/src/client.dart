part of '../tg.dart';

class Client extends t.Client {
  Client({
    required this.receiver,
    required this.sender,
    required this.obfuscation,
    required Session? session,
  }) : _session = session {
    _idSeq._lastSentMessageId = session?.lastSentMessageId ?? 0;
    _idSeq._seqno = session?.seqno ?? 0;
  }

  Session? _session;

  final Obfuscation obfuscation;
  final Stream<Uint8List> receiver;
  final Sink<List<int>> sender;

  late final _EncryptedTransformer? _trns;

  final _idSeq = _MessageIdSequenceGenerator();

  //final Set<int> _msgsToAck = {};

  final Map<int, Completer<t.Result>> _pending = {};
  // final List<int> _msgsToAck = [];

  final _streamController = StreamController<UpdatesBase>.broadcast();
  final _sessionController = StreamController<Session>.broadcast();

  Stream<UpdatesBase> get stream => _streamController.stream;
  Stream<Session> get session => _sessionController.stream;

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
    }
  }

  Future<Session> connect() async {
    sender.add(obfuscation.preamble);
    await Future.delayed(Duration(milliseconds: 100));

    Future<Session> createSession() async {
      final uot = _UnEncryptedTransformer(
        receiver,
        obfuscation,
      );

      final dh = _DiffieHellman(sender, uot.stream, obfuscation, _idSeq.next);
      final authKey = await dh.exchange();

      await uot.dispose();

      final random = Random();
      final sessionId = random.nextInt(1 << 32);

      final session = Session(id: sessionId, authKey: authKey);

      return session;
    }

    final s = _session ??= await createSession();

    _trns = _EncryptedTransformer(
      receiver,
      s.authKey,
      obfuscation,
    );

    _trns?.stream.listen((v) {
      print(v);
      _handleIncomingMessage(v);
    });

    return s;
  }

  void dispose() async {
    // await _trns?.dispose();
  }

  @override
  Future<t.Result<t.TlObject>> invoke(t.TlMethod method) async {
    final session = _session ??= await connect();

    final auth = session.authKey;

    final preferEncryption = auth.id != 0;

    final completer = Completer<t.Result>();
    final m = _idSeq.next(preferEncryption);

    session.lastSentMessageId = _idSeq._lastSentMessageId;
    session.seqno = _idSeq._seqno;

    _sessionController.add(session);

    // if (preferEncryption && _msgsToAck.isNotEmpty) {
    //   final ack = idSeq.next(false);
    //   final ackMsg = MsgsAck(msgIds: _msgsToAck.toList());
    //   _msgsToAck.clear();

    //   final container = MsgContainer(
    //     messages: [
    //       Msg(
    //         msgId: m.msgId,
    //         seqno: m.seqno,
    //         bytes: 0,
    //         body: msg,
    //       ),
    //       Msg(
    //         msgId: ack.msgId,
    //         seqno: ack.seqno,
    //         bytes: 0,
    //         body: ackMsg,
    //       )
    //     ],
    //   );

    //   return send(container, false);
    // }

    _pending[m.id] = completer;
    final buffer = auth.id == 0
        ? _encodeNoAuth(method, m)
        : _encodeWithAuth(method, m, session.id, auth);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    sender.add(Uint8List.fromList(buffer));

    return completer.future;
  }
}
