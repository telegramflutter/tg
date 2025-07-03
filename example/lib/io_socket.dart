import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:tg/tg.dart' as tg;

class IoSocket extends tg.SocketAbstraction {
  IoSocket(this.socket);

  final Socket socket;

  @override
  Stream<Uint8List> get receiver => socket;

  @override
  Future<void> send(List<int> data) async {
    socket.add(data);
    await socket.flush();
  }
}
