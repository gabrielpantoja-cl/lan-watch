# Alert voices

Generated offline with [Piper](https://github.com/rhasspy/piper) and the `en_US-kristin-medium` voice
(trained on public-domain LibriVox recordings), then normalized with ffmpeg.

| File | Text |
|---|---|
| `unknown.wav` | "Hey... a new, unknown device has just connected to your network." |
| `conflict.wav` | "Careful... two devices are claiming the same address. Someone may be spoofing your network." |

Regenerate or change the voice:

```bash
python3 -m venv venv && venv/bin/pip install piper-tts
echo "Hey... a new, unknown device has just connected to your network." \
  | venv/bin/piper -m en_US-kristin-medium.onnx --length-scale 1.22 --noise-scale 0.6 -f raw.wav
ffmpeg -i raw.wav -ac 1 -ar 22050 -af "afade=t=in:d=0.04,loudnorm=I=-20:TP=-2,aecho=0.8:0.5:40:0.15" unknown.wav
```

Any WAV works: point `[sound].unknown` / `[sound].conflict` in `config.toml` to your own files.
