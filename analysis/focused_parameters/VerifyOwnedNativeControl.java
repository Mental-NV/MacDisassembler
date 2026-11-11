// Separate script runs only AFTER the first script's transaction has ended.
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class VerifyOwnedNativeControl extends OwnedNativeControls {
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();JsonObject spec=initializeControl(args);
        Path dir=Path.of(args[0]).getParent(),stagePath=dir.resolve("control-stage.json");
        if(Files.size(stagePath)>8*1024*1024)throw new IllegalStateException("Stage size limit");
        byte[] stageBytes=Files.readAllBytes(stagePath);
        JsonObject stage=JsonParser.parseString(new String(stageBytes,StandardCharsets.UTF_8)).getAsJsonObject();
        if(!stage.keySet().equals(Set.of("schema","status","control_request_sha256","before","observation"))||
           !"macscope-owned-native-control-stage/1".equals(text(stage,"schema"))||
           !"refusal_observed".equals(text(stage,"status"))||
           !hash(Files.readAllBytes(dir.resolve("control.json"))).equals(text(stage,"control_request_sha256")))
            throw new IllegalStateException("Wrong pending stage");
        JsonObject out=stage.getAsJsonObject("observation");String kind=text(spec,"control");
        String refusal=switch(kind) {
            case "prep_digest" -> "Program extent bytes differ from the verified slice";
            case "prep_rollback" -> "Invalid tail-call source or destination";
            case "ast_scope" -> "Native operation outside independently pinned extent";
            default -> throw new IllegalStateException("Control kind");
        };
        if(!CONTROL.equals(text(out,"schema"))||!kind.equals(text(out,"control"))||!OWNED.equals(text(out,"image_sha256"))||
           !text(spec,"request_sha256").equals(text(out,"request_sha256"))||!"refusal_observed".equals(text(out,"status"))||
           !refusal.equals(text(out,"refusal"))||!trial.get("caller").equals(out.get("caller"))||
           !trial.get("callee").equals(out.get("callee"))||out.get("commit_calls").getAsInt()!=0||
           out.get("inference_attempted").getAsBoolean()||out.get("native_graph_exported").getAsBoolean())
            throw new IllegalStateException("Unbound or unsafe stage observation");
        String before=text(stage,"before"),after=snapshot();
        if(before.getBytes(StandardCharsets.UTF_8).length>4*1024*1024 || !before.equals(after)||
           !hash(before.getBytes(StandardCharsets.UTF_8)).equals(text(out,"before_sha256")))
            throw new IllegalStateException("State not restored after script transaction boundary");
        if(Files.exists(dir.resolve("controlled-focus.json")))throw new IllegalStateException("Unexpected focus report");
        JsonObject snapshots=new JsonObject();snapshots.addProperty("before",before);snapshots.addProperty("after",after);
        Files.writeString(dir.resolve("control-snapshots.json"),JSON.toJson(snapshots),StandardOpenOption.CREATE_NEW);
        out.addProperty("status","expected_refusal");out.addProperty("after_sha256",hash(after.getBytes(StandardCharsets.UTF_8)));
        out.addProperty("stage_sha256",hash(stageBytes));
        Files.writeString(Path.of(args[1]+".control.json"),JSON.toJson(out),StandardOpenOption.CREATE_NEW);
        // No HighFunction is present in this script; no inference or bridge export.
    }
}
