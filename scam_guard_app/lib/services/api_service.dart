import 'dart:convert';
import 'package:http/http.dart' as http;

/// Handles all calls to the Scam Guard FastAPI backend.
///
/// IMPORTANT - networking notes for your team:
/// - Android EMULATOR cannot reach your laptop via 127.0.0.1/localhost.
///   It must use 10.0.2.2, which is a special alias the emulator maps
///   back to your host machine's localhost.
/// - A REAL PHONE on the same WiFi network needs your laptop's actual
///   local IP address instead (e.g. 192.168.1.5) - find it with
///   `ipconfig` (Windows) and update baseUrl below before demo day.
/// - iOS simulator (Mac only) can actually use 127.0.0.1 directly.
class ApiService {
  // Change this line depending on how you're testing:
  static final String baseUrl = _resolveBaseUrl();

  static String _resolveBaseUrl() {
    // Default: Android emulator address.
    // Swap to your laptop's WiFi IP (e.g. 'http://192.168.1.5:8000')
    // when testing on a real phone.
    return 'http://10.0.2.2:8000';
  }

  static Future<Map<String, dynamic>> scanMessage({
    required String message,
    String lang = 'en',
    String userId = 'demo_user',
  }) async {
    final response = await http.post(
      Uri.parse('$baseUrl/scan'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'message': message,
        'lang': lang,
        'user_id': userId,
      }),
    );

    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Scan failed: ${response.statusCode} ${response.body}');
    }
  }

  static Future<String> getDigestPreview({
    required String userId,
    int days = 7,
  }) async {
    final response = await http.get(
      Uri.parse('$baseUrl/digest/$userId?days=$days'),
    );

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      return data['digest_text'] as String;
    } else {
      throw Exception('Digest fetch failed: ${response.statusCode}');
    }
  }
}
