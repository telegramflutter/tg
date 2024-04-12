part of '../tg.dart';

InputCheckPasswordSRP check2FA(
  AccountPassword accountPassword,
  String password,
) {
  final currentAlgo = accountPassword.currentAlgo;
  final newAlgo = accountPassword.newAlgo;

  final algo = currentAlgo != null &&
          currentAlgo
              is PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow
      ? currentAlgo
      : newAlgo
          as PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow;

  if (algo == newAlgo) {
    // TODO
    // final saltRandom = Uint8List(32);
    // _rng.getBytes(saltRandom);
    // final salt1 = [
    //   ...algoTmp.salt1, /*...saltRandom*/
    // ];
  }

  final salt1 = [...algo.salt1];
  final salt2 = [...algo.salt2];

  final g = BigInt.from(algo.g);
  final p = _bigEndianInteger(algo.p);

  _checkGoodPrime(p, algo.g);
  final passwordBytes = utf8.encode(password);

  final x1 = [...salt1, ...passwordBytes, ...salt1];
  final hash0 = sha256.convert(x1).bytes;
  final x2 = [...salt2, ...hash0.take(32), ...salt2];
  final hash = sha256.convert(x2).bytes;

  final params = pc.Pbkdf2Parameters(Uint8List.fromList(salt1), 100000, 64);
  final derive = pc.PBKDF2KeyDerivator(pc.HMac.withDigest(pc.SHA512Digest()));

  derive.init(params);

  final pbkdf2 = derive.process(Uint8List.fromList(hash));

  final x3 = [...salt2, ...pbkdf2.take(64), ...salt2];
  final x = _bigEndianInteger(sha256.convert(x3).bytes);
  final v = g.modPow(x, p);

  // If we're computing a new password
  if (accountPassword.currentAlgo == null) {
    return InputCheckPasswordSRP(
      a: v.to256Bytes(),
      srpId: 0,
      m1: Uint8List(0),
    );
  }

  final gB = _bigEndianInteger(accountPassword.srpB!);
  final gB256 = gB.to256Bytes();
  final g_256 = g.to256Bytes();

  final kh = sha256.convert([...algo.p.take(256), ...g_256.take(256)]).bytes;
  final k = _bigEndianInteger(kh);
  final kV = (k * v) % p;

  final a = _bigEndianInteger(Int256.random().data);
  final gA = g.modPow(a, p);
  final gA256 = gA.to256Bytes();

  final uux = sha256.convert([...gA256, ...gB256]).bytes;
  final u = _bigEndianInteger(uux);

  var t = (gB - kV) % p;

  // Positive modulo, if the result is negative increment by p.
  if (t.sign < 0) {
    t += p;
  }

  final sA = t.modPow(a + u * x, p);
  final kA = sha256.convert(sA.to256Bytes()).bytes;

  final phash = sha256.convert(algo.p).bytes;
  final h2 = sha256.convert(g_256).bytes;
  for (int i = 0; i < 32; i++) {
    phash[i] ^= h2[i];
  }
  final hs1 = sha256.convert(salt1).bytes;
  final hs2 = sha256.convert(salt2).bytes;

  final xf = [
    ...phash.take(32),
    ...hs1.take(32),
    ...hs2.take(32),
    ...gA256,
    ...gB256,
    ...kA.take(32),
  ];

  final m1 = sha256.convert(xf).bytes;

  return InputCheckPasswordSRP(
    a: gA256,
    m1: Uint8List.fromList(m1),
    srpId: accountPassword.srpId!,
  );
}
