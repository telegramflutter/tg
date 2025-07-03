part of '../tg.dart';

class _DiffieHellman {
  _DiffieHellman(
    this.socket,
    this.receiver,
    this.obfuscation,
    this.idGenerator,
    this._msgsToAck,
  ) {
    receiver.listen(_onMessage);
  }

  final Obfuscation? obfuscation;
  final Stream<TlObject> receiver;
  final SocketAbstraction socket;
  final Set<int> _msgsToAck;

  void _onMessage(TlObject msg) {
    if (msg is ResPQ) {
      final key = msg.nonce.toString();

      final task = _dicResPQ[key];
      task?.complete(msg);
      _dicResPQ.remove(key);
    } else if (msg is ServerDHParamsOk) {
      final key = '${msg.nonce}-${msg.serverNonce}';

      final task = _dicReqDHParams[key];
      task?.complete(msg);
      _dicReqDHParams.remove(key);
    } else if (msg is DhGenOk) {
      final key = '${msg.nonce}-${msg.serverNonce}';

      final task = _reqSetClientDHParams[key];
      task?.complete(msg);
      _reqSetClientDHParams.remove(key);
    } else if (msg is DhGenRetry) {
      final key = '${msg.nonce}-${msg.serverNonce}';

      final task = _reqSetClientDHParams[key];
      task?.complete(msg);
      _reqSetClientDHParams.remove(key);
    } else if (msg is DhGenFail) {
      final key = '${msg.nonce}-${msg.serverNonce}';

      final task = _reqSetClientDHParams[key];
      task?.complete(msg);
      _reqSetClientDHParams.remove(key);
    }
  }

  final MessageIdGenerator idGenerator;

  final Map<String, Completer<ResPQ>> _dicResPQ = {};
  final Map<String, Completer<ServerDHParamsOk>> _dicReqDHParams = {};
  final Map<String, Completer<SetClientDHParamsAnswerBase>>
      _reqSetClientDHParams = {};

  Future<ResPQ> _reqPqMulti([Int128? nonce]) async {
    final completer = Completer<ResPQ>();
    final m = idGenerator._next(false);

    nonce ??= Int128.random();
    final msg = ReqPqMulti(nonce: nonce);
    final key = msg.nonce.toString();
    _dicResPQ[key] = completer;

    final buffer = _encodeNoAuth(msg, m);

    obfuscation?.send.encryptDecrypt(buffer, buffer.length);
    await socket.send(buffer);

    return completer.future;
  }

  Future<ServerDHParamsOk> _reqDHParams(
    ResPQ resPQ,
    Int256 newNonce, {
    int? dc,
  }) async {
    final fingerprint = resPQ.serverPublicKeyFingerprints
        .firstWhere((x) => rsaKeys[x] != null, orElse: () => 0);

    final publicKey = rsaKeys[fingerprint]!;
    final n = _bigEndianInteger(publicKey.n);
    final e = _bigEndianInteger(publicKey.e);

    final pq = resPQ.pq.buffer.asByteData().getUint64(0, Endian.big);
    final p = _pqFactorize(pq);
    final q = pq ~/ p;

    final pqInnerData = PQInnerDataDc(
      pq: resPQ.pq,
      p: _int64ToBigEndian(p),
      q: _int64ToBigEndian(q),
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      newNonce: newNonce,
      dc: dc ?? 0,
    );

    Uint8List? encryptedData;
    do {
      final clearBuffer = Uint8List(256);

      final aesKey = Uint8List(32);
      final zeroIV = Uint8List(32);

      _rng.getBytes(aesKey);
      clearBuffer.setRange(0, 32, aesKey);

      final msg = pqInnerData.asUint8List();
      clearBuffer.setRange(32, 32 + msg.length, msg);

      // length before padding
      final clearLength = msg.length;

      _rng.getBytes(
        clearBuffer,
        clearLength + 32,
        192 - clearLength,
      );

      final hash = sha256(clearBuffer.take(192 + 32).toList());
      clearBuffer.setRange(192 + 32, 192 + 32 + hash.length, hash);
      clearBuffer.reverse(32, 192);

      final aesEncrypted = _aesIgeEncryptDecrypt(
        Uint8List.fromList(clearBuffer.skip(32).take(224).toList()),
        AesKeyIV(aesKey, zeroIV),
        true,
      );

      final hashAes = sha256(aesEncrypted);

      for (int i = 0; i < 32; i++) // prefix aes_encrypted with temp_key_xor
      {
        clearBuffer[i] = (aesKey[i] ^ hashAes[i]) % 256;
      }

      clearBuffer.setRange(32, 256, aesEncrypted);

      final x = _bigEndianInteger(clearBuffer);

      if (x < n) // if good result, encrypt with RSA key:
      {
        final mp = x.modPow(e, n);
        encryptedData = mp.toBytes(Endian.big);
      }
    } while (encryptedData == null);

    final reqDHParams = ReqDHParams(
      p: _int64ToBigEndian(p),
      q: _int64ToBigEndian(q),
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      encryptedData: encryptedData,
      publicKeyFingerprint: fingerprint,
    );

    final completer = Completer<ServerDHParamsOk>();
    final m = idGenerator._next(false);

    final msg = reqDHParams;
    final key = '${msg.nonce}-${msg.serverNonce}';
    _dicReqDHParams[key] = completer;

    // if (msg is SetClientDHParams) {
    //   final key = '${msg.nonce}-${msg.serverNonce}';
    //   _reqSetClientDHParams[key] = completer;
    // }

    final buffer = _encodeNoAuth(msg, m);

    obfuscation?.send.encryptDecrypt(buffer, buffer.length);
    socket.send(Uint8List.fromList(buffer));
    return completer.future;
  }

  Future<SetClientDHParamsAnswerBase> _setClientDHParams(
    ResPQ resPQ,
    BigInt gB,
    int retryId,
    AesKeyIV keys,
  ) async {
    final clientDHinnerData = ClientDHInnerData(
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      retryId: retryId,
      gB: gB.toBytes(Endian.big),
    );

    final messageBuffer = clientDHinnerData.asUint8List();
    final totalLength = messageBuffer.length + 20;
    final paddingToAdd = (0x7FFFFFF0 - totalLength) % 16;
    final padding = Uint8List(paddingToAdd);
    _rng.getBytes(padding);

    final messageHash = sha1(messageBuffer);

    final clearStream = [...messageHash, ...messageBuffer, ...padding];
    final encryptedData = _aesIgeEncryptDecrypt(
      Uint8List.fromList(clearStream),
      keys,
      true,
    );

    final setClientDHParams = SetClientDHParams(
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      encryptedData: encryptedData,
    );

    final completer = Completer<SetClientDHParamsAnswerBase>();
    final m = idGenerator._next(false);

    final msg = setClientDHParams;
    final key = '${msg.nonce}-${msg.serverNonce}';
    _reqSetClientDHParams[key] = completer;

    final buffer = _encodeNoAuth(msg, m);

    obfuscation?.send.encryptDecrypt(buffer, buffer.length);
    socket.send(Uint8List.fromList(buffer));
    return completer.future;
  }

  Future<AuthorizationKey> _createAuthKey(
    ResPQ resPQ,
    ServerDHParamsOk serverDHparams,
    Int256 newNonce, {
    int? dc,
  }) async {
    final pq = resPQ.pq.buffer.asByteData().getUint64(0, Endian.big);
    final p = _pqFactorize(pq);
    final q = pq ~/ p;

    final pqInnerData = PQInnerDataDc(
      pq: resPQ.pq,
      p: _int64ToBigEndian(p),
      q: _int64ToBigEndian(q),
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      newNonce: newNonce,
      dc: dc ?? 0,
    );

    final keys = _constructTmpAESKeyIV(resPQ.serverNonce, pqInnerData.newNonce);
    final answer = _aesIgeEncryptDecrypt(
      serverDHparams.encryptedAnswer,
      keys,
      false,
    );

    final answerReader = BinaryReader(answer);
    final answerHash = answerReader.readRawBytes(20);
    final answerObj = answerReader.readObject();

    if (answerObj is! ServerDHInnerData) {
      throw Exception('ServerDHInnerData expected.');
    }

    final paddingLength = answer.length - answerReader.position;
    final hash =
        sha1(answer.skip(20).take(answer.length - paddingLength - 20).toList());

    print('${_hex(answerHash)} == ${_hex(hash)}');

    final gA = _bigEndianInteger(answerObj.gA);
    final dhPrime = _bigEndianInteger(answerObj.dhPrime);

    _checkGoodPrime(dhPrime, answerObj.g);

    // TODO (xclud):
    //final localTime = DateTime.now().toUtc();
    idGenerator._lastSentMessageId = 0;
    //idGenerator.serverTicksOffset = (answerObj.serverTime.difference(localTime)).ticks;

    final salt = Uint8List(256);
    _rng.getBytes(salt);
    final b = _bigEndianInteger(salt);

    final gB = BigInt.from(answerObj.g).modPow(b, dhPrime);
    _checkGoodGaAndGb(gA, dhPrime);
    _checkGoodGaAndGb(gB, dhPrime);

    var retryId = 0;
    final setClientDHparamsAnswer = await _setClientDHParams(
      resPQ,
      gB,
      retryId,
      keys,
    );

    //7)
    final gab = gA.modPow(b, dhPrime);
    final authKey = gab.toBytes(Endian.big);
    //8)
    final authKeyHash = sha1(authKey);
    // (auth_key_aux_hash)
    retryId = BinaryReader(Uint8List.fromList(authKeyHash)).readInt64(false);
    //9)
    // if (setClientDHparamsAnswer is not DhGenOk dhGenOk) throw new WTException("not dh_gen_ok");
    // if (dhGenOk.nonce != nonce) throw new WTException("Nonce mismatch");
    // if (dhGenOk.server_nonce != resPQ.server_nonce) throw new WTException("Server Nonce mismatch");

    final expectedNewNonceN = [
      ...pqInnerData.newNonce.data,
      1,
      ...authKeyHash.take(8),
    ];

    final expectedNewNonceNHash = sha1(expectedNewNonceN);
    final result = setClientDHparamsAnswer;

    if (result is DhGenOk) {
      print(
          '0x${_hex(expectedNewNonceNHash.skip(4))} == ${result.newNonceHash1}');
    }

    final authKeyID =
        BinaryReader(Uint8List.fromList(authKeyHash.skip(12).toList()))
            .readInt64(false);

    final saltLeft = BinaryReader(Uint8List.fromList(pqInnerData.newNonce.data))
        .readInt64(false);

    final saltRight = BinaryReader(Uint8List.fromList(resPQ.serverNonce.data))
        .readInt64(false);

    final ak = AuthorizationKey._(
      authKeyID,
      authKey,
      saltLeft ^ saltRight,
      _msgsToAck,
    );

    return ak;
  }

  Future<AuthorizationKey> exchange() async {
    final newNonce = Int256.random();
    final resPQ = await _reqPqMulti();
    await Future.delayed(const Duration(milliseconds: 200));
    final serverDHparams = await _reqDHParams(resPQ, newNonce);
    await Future.delayed(const Duration(milliseconds: 200));
    final ak = await _createAuthKey(
      resPQ,
      serverDHparams,
      newNonce,
    );

    return ak;
  }
}
