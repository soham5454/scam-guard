import 'package:flutter/material.dart';
import '../theme/colors.dart';
import 'result_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final TextEditingController _messageController = TextEditingController();

  // A couple of pre-written demo messages so you don't have to type
  // during a live demo - just tap and go.
  static const String demoScamMessage =
      'Your electricity connection will be cut tonight. Pay immediately: bit.ly/xyz123';
  static const String demoSafeMessage =
      'Hey, are we still meeting for lunch tomorrow?';

  void _goToResult(String message) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ResultScreen(originalMessage: message),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.paper,
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(22, 16, 22, 28),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'HELLO,',
                style: TextStyle(
                  color: AppColors.marigold,
                  fontWeight: FontWeight.bold,
                  fontSize: 13,
                  letterSpacing: 1.5,
                ),
              ),
              const SizedBox(height: 4),
              const Text(
                'Scam Guard',
                style: TextStyle(
                  color: AppColors.ink,
                  fontWeight: FontWeight.w800,
                  fontSize: 30,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                'Got a suspicious message? Paste it below.',
                style: TextStyle(color: AppColors.ink.withValues(alpha: 0.65), fontSize: 15),
              ),
              const SizedBox(height: 20),

              // Message input box - stands in for the "share intent" flow
              // for now; wire up receive_sharing_intent package later.
              Container(
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: AppColors.ink.withValues(alpha: 0.2), width: 1.5),
                ),
                padding: const EdgeInsets.all(14),
                child: TextField(
                  controller: _messageController,
                  maxLines: 4,
                  decoration: const InputDecoration(
                    hintText: 'Paste or type a suspicious SMS/WhatsApp message here...',
                    border: InputBorder.none,
                  ),
                ),
              ),
              const SizedBox(height: 12),

              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.ink,
                    foregroundColor: AppColors.paper,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(999),
                    ),
                  ),
                  onPressed: () {
                    final text = _messageController.text.trim();
                    if (text.isNotEmpty) _goToResult(text);
                  },
                  child: const Text('Scan Message',
                      style: TextStyle(fontWeight: FontWeight.bold, fontSize: 15)),
                ),
              ),
              const SizedBox(height: 20),

              Text(
                'OR TRY A DEMO MESSAGE',
                style: TextStyle(
                  color: AppColors.ink.withValues(alpha: 0.4),
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                  letterSpacing: 1,
                ),
              ),
              const SizedBox(height: 10),

              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.danger,
                        side: BorderSide(color: AppColors.danger),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(999),
                        ),
                      ),
                      onPressed: () => _goToResult(demoScamMessage),
                      child: const Text('Scam example'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: OutlinedButton(
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.safe,
                        side: BorderSide(color: AppColors.safe),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(999),
                        ),
                      ),
                      onPressed: () => _goToResult(demoSafeMessage),
                      child: const Text('Safe example'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
