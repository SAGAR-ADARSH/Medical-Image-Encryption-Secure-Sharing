package com.medicalsecurity.util;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Generates synthetic sample images for the demo and the automated tests.
 * The generated files are abstract graphics - they contain NO patient data
 * and are safe to redistribute and commit-free (generated on demand).
 */
public final class SampleImageGenerator {

    private SampleImageGenerator() {
    }

    /** Synthetic 640x480 PNG resembling an abstract scan placeholder. */
    public static byte[] generateSyntheticImage() {
        return generateSyntheticImage(640, 480);
    }

    public static byte[] generateSyntheticImage(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            // Background gradient.
            for (int y = 0; y < height; y++) {
                int shade = 20 + (y * 90 / Math.max(1, height));
                g.setColor(new Color(shade, shade + 10, shade + 30));
                g.drawLine(0, y, width, y);
            }
            // Abstract "scan" rings.
            g.setColor(new Color(90, 160, 220, 160));
            for (int r = Math.min(width, height) / 2; r > 20; r -= 18) {
                g.drawOval(width / 2 - r, height / 2 - r, r * 2, r * 2);
            }
            g.setColor(new Color(220, 220, 230));
            g.fillOval(width / 2 - 24, height / 2 - 24, 48, 48);
            // Label so nobody mistakes it for real data.
            g.setColor(Color.YELLOW);
            g.setFont(new Font(Font.MONOSPACED, Font.BOLD, Math.max(12, width / 32)));
            g.drawString("SYNTHETIC SAMPLE - NOT REAL PATIENT DATA", 12, height - 16);
            // Grid marks.
            g.setColor(new Color(255, 255, 255, 60));
            for (int x = 0; x < width; x += 40) {
                g.drawLine(x, 0, x, height);
            }
            for (int y = 0; y < height; y += 40) {
                g.drawLine(0, y, width, y);
            }
        } finally {
            g.dispose();
        }
        return toPngBytes(image);
    }

    /** Encodes a buffered image as PNG bytes (pixels unaltered). */
    public static byte[] toPngBytes(BufferedImage image) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            ImageIO.write(image, "png", buffer);
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("PNG encoding failed", e);
        }
    }

    /** Writes the synthetic sample to disk and returns the path. */
    public static Path writeSample(Path target) throws IOException {
        byte[] png = generateSyntheticImage();
        if (target.getParent() != null) {
            Files.createDirectories(target.getParent());
        }
        OutputStream out = Files.newOutputStream(target);
        try {
            out.write(png);
        } finally {
            out.close();
        }
        return target;
    }
}
