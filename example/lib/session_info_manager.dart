import 'package:shared_preferences/shared_preferences.dart' show SharedPreferences;
import 'package:tg/tg.dart' as tg;

class SessionInfoManager extends tg.SessionInfoManager {

  SessionInfoManager({
    required tg.AuthorizationKey authorizationKey,
  }) : super(authorizationKey: authorizationKey) {
    prefKey = '${authorizationKey.id}-${authorizationKey.key.join()}';
  }

  late final String  prefKey;

  @override
  Future<void> updateSeqno(int id, int seqnoCounter) async {
    final prefs = await SharedPreferences.getInstance();
    prefs.setString(prefKey, '$id,$seqnoCounter');
  }

  Future<(int id, int seqnoCounter)> getSeqno({ tg.AuthorizationKey? authorizationKey }) async {
    final prefs = await SharedPreferences.getInstance();
    final seqno = prefs.getString(prefKey);

    if (seqno == null) {
      return (0, 0);
    }

    final parts = seqno.split(',');
    return (int.parse(parts[0]), int.parse(parts[1]));
  }
}