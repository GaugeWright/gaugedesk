/** Audio sent to dictation is a bounded 16 kHz mono WAV, independent of the
 * browser's MediaRecorder codec. No recorded bytes enter the Session. */
export const MAX_DICTATION_SECONDS = 30;
export const MAX_DICTATION_BYTES = 1_000_044;

export async function recordedAudioAsWav(recording: Blob): Promise<Blob> {
    const context = new AudioContext();
    try {
        const decoded = await context.decodeAudioData(await recording.arrayBuffer());
        if (decoded.duration <= 0 || decoded.duration > MAX_DICTATION_SECONDS + 1) {
            throw new Error("Record at most 30 seconds.");
        }
        const frames = Math.ceil(decoded.duration * 16_000);
        const offline = new OfflineAudioContext(1, frames, 16_000);
        const source = offline.createBufferSource();
        source.buffer = decoded;
        source.connect(offline.destination);
        source.start();
        const rendered = await offline.startRendering();
        const samples = rendered.getChannelData(0);
        const bytes = new ArrayBuffer(44 + samples.length * 2);
        const view = new DataView(bytes);
        const ascii = (offset: number, value: string) => {
            for (let i = 0; i < value.length; i++) view.setUint8(offset + i, value.charCodeAt(i));
        };
        ascii(0, "RIFF");
        view.setUint32(4, bytes.byteLength - 8, true);
        ascii(8, "WAVE");
        ascii(12, "fmt ");
        view.setUint32(16, 16, true);
        view.setUint16(20, 1, true);
        view.setUint16(22, 1, true);
        view.setUint32(24, 16_000, true);
        view.setUint32(28, 32_000, true);
        view.setUint16(32, 2, true);
        view.setUint16(34, 16, true);
        ascii(36, "data");
        view.setUint32(40, samples.length * 2, true);
        samples.forEach((sample, i) => {
            const clamped = Math.max(-1, Math.min(1, sample));
            view.setInt16(44 + i * 2, clamped < 0 ? clamped * 32768 : clamped * 32767, true);
        });
        if (bytes.byteLength > MAX_DICTATION_BYTES) throw new Error("Recording is too long.");
        return new Blob([bytes], { type: "audio/wav" });
    } finally {
        await context.close();
    }
}
