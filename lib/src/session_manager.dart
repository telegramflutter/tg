part of '../tg.dart';

class SessionInfo {
  SessionInfo({
    required this.authorizationKey,
    required this.seqno,
  });

  final AuthorizationKey authorizationKey;
  final String seqno;
}

abstract class SessionInfoManager {
  Future<void> updateSeqno(int id, int seqno);
}