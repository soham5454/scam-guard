import 'dart:async';
import 'package:flutter/material.dart';
import 'package:receive_sharing_intent/receive_sharing_intent.dart';
import 'theme/colors.dart';
import 'screens/home_screen.dart';
import 'screens/result_screen.dart';
import 'screens/notification_test_screen.dart';

final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

void main() {
  runApp(const ScamGuardApp());
}

class ScamGuardApp extends StatefulWidget {
  const ScamGuardApp({super.key});

  @override
  State<ScamGuardApp> createState() => _ScamGuardAppState();
}

class _ScamGuardAppState extends State<ScamGuardApp> {
  StreamSubscription? _intentSub;

  @override
  void initState() {
    super.initState();
    _listenForSharedText();
  }

  void _listenForSharedText() {
    // App already running in background, user shares text into it.
    _intentSub = ReceiveSharingIntent.instance.getMediaStream().listen(
      (List<SharedMediaFile> files) {
        _handleSharedFiles(files);
      },
      onError: (err) {
        debugPrint('Share stream error: $err');
      },
    );

    // App was closed, launched fresh via a share action.
    ReceiveSharingIntent.instance.getInitialMedia().then((List<SharedMediaFile> files) {
      _handleSharedFiles(files);
    });
  }

  void _handleSharedFiles(List<SharedMediaFile> files) {
    if (files.isEmpty) return;
    final sharedText = files.first.path;
    if (sharedText.trim().isEmpty) return;

    navigatorKey.currentState?.push(
      MaterialPageRoute(
        builder: (_) => ResultScreen(originalMessage: sharedText.trim()),
      ),
    );

    // Clear it so the same shared text doesn't re-trigger navigation.
    ReceiveSharingIntent.instance.reset();
  }

  @override
  void dispose() {
    _intentSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: navigatorKey,
      title: 'Scam Guard',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        scaffoldBackgroundColor: AppColors.paper,
        primaryColor: AppColors.ink,
        fontFamily: 'Roboto', // swap for Noto Sans / Baloo 2 once fonts are bundled
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: AppColors.ink,
          background: AppColors.paper,
        ), // ColorScheme.fromSeed
      ), // ThemeData
      home: const NotificationTestScreen(),
    ); // MaterialApp
  }
}