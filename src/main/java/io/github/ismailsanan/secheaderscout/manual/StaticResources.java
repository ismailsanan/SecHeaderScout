package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.util.Locale;
import java.util.Set;

/** Recognises images, scripts, stylesheets, fonts and media, which Deep Scan skips by default. */
final class StaticResources {

    private static final Set<String> EXTENSIONS = Set.of(
            "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp",
            "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav", "wasm");

    private StaticResources() {
    }

    /** By the declared Content-Type; by the file extension only when no Content-Type was sent. */
    static boolean isStatic(ResponseSnapshot snapshot) {
        if (snapshot.htmlDocument()) {
            return false;
        }
        String type = snapshot.headers().first("Content-Type").orElse("")
                .split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        if (type.isEmpty()) {
            return EXTENSIONS.contains(extension(snapshot.url()));
        }
        return type.startsWith("image/") || type.startsWith("font/") || type.startsWith("audio/") || type.startsWith("video/")
                || type.equals("text/css") || type.contains("javascript") || type.equals("application/wasm");
    }

    static String extension(String url) {
        String path = UrlPaths.path(url);
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        return dot > slash && dot < path.length() - 1 ? path.substring(dot + 1).toLowerCase(Locale.ROOT) : "";
    }
}
