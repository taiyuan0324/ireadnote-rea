// Ghidra postScript: export decompiled C for matched functions.
// Usage: ExportIREAFunctions.java <outDir> <patternsFile|ALL> [shardIndex] [shardCount]
//   patternsFile : one regex per line (UTF-8, '#' comments). "ALL" = match every function.
//   shardIndex   : 0-based shard id (optional, default 0)
//   shardCount   : total shards (optional, default 1)
// Sharding is by function ordinal, so N parallel jobs each do 1/N of the decompile work.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class ExportIREAFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: usage: ExportIREAFunctions.java <outDir> <patternsFile|ALL> [shardIndex] [shardCount]");
            return;
        }
        Path outDir = Paths.get(args[0]);
        Files.createDirectories(outDir);

        boolean all = args.length >= 2 && "ALL".equalsIgnoreCase(args[1].trim());
        int shardIndex = 0, shardCount = 1;
        if (args.length >= 3) { try { shardIndex = Integer.parseInt(args[2].trim()); } catch (Exception ignored) {} }
        if (args.length >= 4) { try { shardCount = Math.max(1, Integer.parseInt(args[3].trim())); } catch (Exception ignored) {} }

        List<Pattern> patterns = new ArrayList<>();
        String[] defaults = {
            "(?i)vip", "(?i)member", "(?i)entitle", "(?i)purchase", "(?i)iap",
            "(?i)storekit", "(?i)receipt", "(?i)reward", "(?i)admanager",
            "(?i)buReward", "(?i)ggReward", "(?i)isMember", "(?i)ownership"
        };
        if (!all && args.length >= 2 && Files.isReadable(Paths.get(args[1]))) {
            for (String line : Files.readAllLines(Paths.get(args[1]), StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                try { patterns.add(Pattern.compile(t, Pattern.CASE_INSENSITIVE)); }
                catch (PatternSyntaxException e) { println("bad pattern skipped: " + t); }
            }
        }
        if (!all && patterns.isEmpty()) {
            for (String d : defaults) patterns.add(Pattern.compile(d));
        }

        FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);
        List<String> index = new ArrayList<>();
        index.add("address,name,signature,matched,decompiled_bytes,shard");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        int total = 0, matched = 0, ok = 0, skippedOtherShard = 0;
        Set<String> usedNames = new HashSet<>();
        while (fns.hasNext()) {
            Function fn = fns.next();
            boolean isThunk = fn.isThunk();
            boolean isExternal = fn.isExternal();
            String name = fn.getName(true);
            int ordinal = total;
            total++;

            boolean inShard = (ordinal % shardCount) == shardIndex;
            if (!inShard) { skippedOtherShard++; continue; }

            boolean match = all;
            if (!all) {
                for (Pattern p : patterns) { if (p.matcher(name).find()) { match = true; break; } }
            }

            String addr = fn.getEntryPoint().toString();
            String sig = fn.getSignature().getPrototypeString();

            if (!match || isExternal) {
                index.add(addr + ",\"" + esc(name) + "\",\"" + esc(sig) + "\",false,0," + shardIndex);
                continue;
            }
            matched++;
            int bytes = 0;
            try {
                DecompileResults r = decomp.decompileFunction(fn, 90, monitor);
                if (r != null && r.decompileCompleted()) {
                    String c = r.getDecompiledFunction().getC();
                    bytes = c == null ? 0 : c.getBytes(StandardCharsets.UTF_8).length;
                    String safe = sanitize(name + "_" + addr.replace("0x", ""));
                    if (usedNames.contains(safe)) safe = safe + "_" + ordinal;
                    usedNames.add(safe);
                    StringBuilder sb = new StringBuilder();
                    sb.append("/* iReadNote REA export\n")
                      .append(" * function : ").append(name).append("\n")
                      .append(" * address  : ").append(addr).append("\n")
                      .append(" * signature: ").append(sig).append("\n")
                      .append(" * thunk    : ").append(isThunk).append("\n")
                      .append(" * NOTE: decompiler pseudocode, not original source.\n */\n\n")
                      .append(c == null ? "" : c);
                    Files.write(outDir.resolve(safe + ".c"), sb.toString().getBytes(StandardCharsets.UTF_8));
                    ok++;
                }
            } catch (Throwable t) {
                println("decompile failed for " + name + ": " + t.getMessage());
            }
            index.add(addr + ",\"" + esc(name) + "\",\"" + esc(sig) + "\",true," + bytes + "," + shardIndex);
            if (matched % 500 == 0) println("progress: shard=" + shardIndex + " matched=" + matched + " exported=" + ok);
        }
        Files.write(outDir.resolve("index.csv"),
                    String.join("\n", index).getBytes(StandardCharsets.UTF_8));
        println("DONE shard=" + shardIndex + "/" + shardCount + " total=" + total +
                " skipped_other_shard=" + skippedOtherShard + " matched=" + matched + " exported=" + ok);
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
    private static String sanitize(String s) {
        return s.replaceAll("[^A-Za-z0-9_.-]", "_");
    }
}
