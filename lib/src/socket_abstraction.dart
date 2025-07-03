part of '../tg.dart';

abstract class SocketAbstraction {
  Stream<Uint8List> get receiver;
  Future<void> send(List<int> data);
}
