import 'dart:typed_data';

import 'package:pointycastle/export.dart';

List<int> sha256(List<int> data) {
  return SHA256Digest().process(Uint8List.fromList(data));
}

List<int> sha1(List<int> data) {
  return SHA1Digest().process(Uint8List.fromList(data));
}
