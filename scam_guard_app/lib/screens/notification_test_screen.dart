import 'package:flutter/material.dart';
import 'package:notification_listener_service/notification_listener_service.dart';
import 'package:another_telephony/telephony.dart';
import '../theme/colors.dart';
import '../services/api_service.dart';

class NotificationTestScreen extends StatefulWidget {
  const NotificationTestScreen({super.key});

  @override
  State<NotificationTestScreen> createState() => _NotificationTestScreenState();
}

class _LogEntry {
  final String source;
  final String content;
  bool scanning;
  bool? isScam;
  String? categoryName;
  String? error;
  bool alertSent = false;

  _LogEntry({required this.source, required this.content, this.scanning = true});
}

class _NotificationTestScreenState extends State<NotificationTestScreen> {
  bool _permissionGranted = false;
  final List<_LogEntry> _log = [];
  final TextEditingController _caretakerController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _checkPermission();
  }

  Future<void> _checkPermission() async {
    final granted = await NotificationListenerService.isPermissionGranted();
    setState(() => _permissionGranted = granted);
    if (granted) _startListening();
  }

  Future<void> _requestPermission() async {
    final granted = await NotificationListenerService.requestPermission();
    setState(() => _permissionGranted = granted);
    if (granted) _startListening();
  }

  void _startListening() {
    NotificationListenerService.notificationsStream.listen((event) {
      if (event.packageName == 'com.example.scam_guard_app') return;
      final content = event.content?.trim() ?? '';
      if (content.isEmpty) return;

      final entry = _LogEntry(
        source: '${event.packageName ?? "unknown"} — ${event.title ?? ""}',
        content: content,
      );
      setState(() => _log.insert(0, entry));
      _scanEntry(entry);
    });
  }

  Future<void> _scanEntry(_LogEntry entry) async {
    try {
      final result = await ApiService.scanMessage(message: entry.content);
      setState(() {
        entry.scanning = false;
        entry.isScam = result['is_scam'] == true;
        final match = result['match'] as Map<String, dynamic>?;
        entry.categoryName = match?['category_name'] as String?;
      });

      if (entry.isScam == true) {
        await _alertCaretaker(entry);
      }
    } catch (e) {
      setState(() {
        entry.scanning = false;
        entry.error = e.toString();
      });
    }
  }

  Future<void> _alertCaretaker(_LogEntry entry) async {
    final caretakerNumber = _caretakerController.text.trim();
    if (caretakerNumber.isEmpty) return;

    final alertMessage =
        'SCAM GUARD ALERT: A suspicious message was just received '
        '(${entry.categoryName ?? "possible scam"}). '
        'Message: "${entry.content}". Please check on them and advise not to click any links.';

    try {
      final telephony = Telephony.instance;
      final hasPermission = await telephony.requestSmsPermissions ?? false;
      if (!hasPermission) {
        debugPrint('SMS permission not granted');
        return;
      }
      await telephony.sendSms(
        to: caretakerNumber,
        message: alertMessage,
      );
      setState(() => entry.alertSent = true);
    } catch (e) {
      debugPrint('Failed to send caretaker alert: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.paper,
      appBar: AppBar(
        title: const Text('Notification Listener Test'),
        backgroundColor: AppColors.paper,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              _permissionGranted
                  ? 'Permission granted — listening for notifications'
                  : 'Permission NOT granted yet',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                color: _permissionGranted ? AppColors.safe : AppColors.danger,
              ),
            ),
            const SizedBox(height: 12),
            if (!_permissionGranted)
              ElevatedButton(
                onPressed: _requestPermission,
                child: const Text('Grant Notification Access'),
              ),
            const SizedBox(height: 16),
            TextField(
              controller: _caretakerController,
              keyboardType: TextInputType.phone,
              decoration: const InputDecoration(
                labelText: "Caretaker's phone number",
                hintText: 'e.g. 9876543210',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            const Text('Live notification log (auto-scanned):', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            Expanded(
              child: ListView.builder(
                itemCount: _log.length,
                itemBuilder: (context, index) {
                  final entry = _log[index];
                  Color statusColor;
                  String statusText;
                  if (entry.scanning) {
                    statusColor = Colors.grey;
                    statusText = 'Scanning...';
                  } else if (entry.error != null) {
                    statusColor = Colors.orange;
                    statusText = 'Scan failed';
                  } else if (entry.isScam == true) {
                    statusColor = AppColors.danger;
                    statusText = 'SCAM: ${entry.categoryName ?? "unknown"}'
                        '${entry.alertSent ? " — caretaker alerted" : ""}';
                  } else {
                    statusColor = AppColors.safe;
                    statusText = 'Looks safe';
                  }
                  return Container(
                    margin: const EdgeInsets.symmetric(vertical: 4),
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: statusColor, width: 1.5),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(entry.source, style: const TextStyle(fontSize: 10, color: Colors.grey)),
                        const SizedBox(height: 2),
                        Text(entry.content, style: const TextStyle(fontSize: 13)),
                        const SizedBox(height: 4),
                        Text(statusText,
                            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: statusColor)),
                      ],
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}