import 'package:flutter/material.dart';
import 'package:flutter_tts/flutter_tts.dart';
import '../theme/colors.dart';
import '../services/api_service.dart';

class ResultScreen extends StatefulWidget {
  final String originalMessage;
  const ResultScreen({super.key, required this.originalMessage});

  @override
  State<ResultScreen> createState() => _ResultScreenState();
}

class _ResultScreenState extends State<ResultScreen> {
  final FlutterTts _tts = FlutterTts();
  bool _loading = true;
  bool _speaking = false;
  String? _error;
  Map<String, dynamic>? _result;

  @override
  void initState() {
    super.initState();
    _scan();
  }

  Future<void> _scan() async {
    try {
      final result = await ApiService.scanMessage(message: widget.originalMessage);
      setState(() {
        _result = result;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _speak(String text) async {
    setState(() => _speaking = true);
    await _tts.setLanguage('en-US');
    await _tts.setSpeechRate(0.45);
    _tts.setCompletionHandler(() {
      if (mounted) setState(() => _speaking = false);
    });
    await _tts.speak(text);
  }

  @override
  void dispose() {
    _tts.stop();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.paper,
      appBar: AppBar(
        backgroundColor: AppColors.paper,
        elevation: 0,
        iconTheme: const IconThemeData(color: AppColors.ink),
      ),
      body: SafeArea(
        child: _loading
            ? const Center(child: CircularProgressIndicator(color: AppColors.ink))
            : _error != null
                ? _buildError()
                : _buildResult(),
      ),
    );
  }

  Widget _buildError() {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.wifi_off, color: AppColors.danger, size: 48),
          const SizedBox(height: 16),
          const Text(
            "Couldn't reach the backend",
            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 18, color: AppColors.ink),
          ),
          const SizedBox(height: 8),
          Text(
            'Check that:\n'
            '1. uvicorn is running on your laptop\n'
            '2. If using the emulator, baseUrl in api_service.dart is 10.0.2.2\n'
            '3. If using a real phone, baseUrl is your laptop\'s WiFi IP and both devices are on the same network\n\n'
            'Error: $_error',
            style: TextStyle(color: AppColors.ink.withValues(alpha: 0.7), fontSize: 13),
          ),
        ],
      ),
    );
  }

  Widget _buildResult() {
    final isScam = _result?['is_scam'] == true;
    final match = _result?['match'] as Map<String, dynamic>?;
    final categoryName = match?['category_name'] ?? 'Unknown';
    final explanation = match?['explanation'] ?? '';

    final speakText = isScam
        ? 'Warning. $categoryName. $explanation'
        : 'This message looks safe.';

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(22, 6, 22, 28),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Center(
            child: Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: isScam ? AppColors.danger : AppColors.safe,
                  width: 3,
                ),
              ),
              alignment: Alignment.center,
              child: Text(
                isScam ? 'DANGER' : 'SAFE',
                style: TextStyle(
                  fontWeight: FontWeight.w800,
                  fontSize: 14,
                  color: isScam ? AppColors.danger : AppColors.safe,
                ),
              ),
            ),
          ),
          const SizedBox(height: 16),
          if (isScam) ...[
            Text(
              categoryName.toString().toUpperCase(),
              textAlign: TextAlign.center,
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 12,
                color: AppColors.danger,
                letterSpacing: 1.2,
              ),
            ),
            const SizedBox(height: 6),
          ],
          Text(
            isScam ? 'This message is not real' : 'This message looks safe',
            textAlign: TextAlign.center,
            style: const TextStyle(
              fontWeight: FontWeight.w800,
              fontSize: 22,
              color: AppColors.ink,
            ),
          ),
          const SizedBox(height: 18),

          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: AppColors.ink.withValues(alpha: 0.15)),
            ),
            child: Text(
              '"${widget.originalMessage}"',
              style: const TextStyle(color: AppColors.ink, fontSize: 14, height: 1.5),
            ),
          ),

          if (isScam) ...[
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppColors.danger.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Why this is dangerous',
                    style: TextStyle(fontWeight: FontWeight.bold, color: AppColors.danger, fontSize: 15),
                  ),
                  const SizedBox(height: 8),
                  Text(explanation.toString(),
                      style: const TextStyle(color: AppColors.ink, fontSize: 13.5, height: 1.6)),
                ],
              ),
            ),
          ],

          const SizedBox(height: 18),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.ink,
                foregroundColor: AppColors.paper,
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(999)),
              ),
              icon: Icon(_speaking ? Icons.volume_up : Icons.volume_up_outlined),
              label: Text(_speaking ? 'Speaking...' : 'Read aloud'),
              onPressed: () => _speak(speakText),
            ),
          ),
        ],
      ),
    );
  }
}
