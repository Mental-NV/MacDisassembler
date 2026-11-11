// Standalone producer-contract check; not a native Ghidra capture.
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class ControlJsonNullCheck {
    public static void main(String[] args) {
        Gson json=new GsonBuilder().serializeNulls().create();
        JsonObject unit=new JsonObject();unit.add("bytes",JsonNull.INSTANCE);
        JsonObject observation=new JsonObject();observation.addProperty("injected_address",(String)null);
        JsonObject stage=new JsonObject();stage.add("observation",observation);
        stage.addProperty("snapshot",json.toJson(unit));
        JsonObject parsed=JsonParser.parseString(json.toJson(stage)).getAsJsonObject();
        JsonObject nested=parsed.getAsJsonObject("observation");
        JsonObject restored=JsonParser.parseString(parsed.get("snapshot").getAsString()).getAsJsonObject();
        if(!nested.has("injected_address")||!nested.get("injected_address").isJsonNull()||
           !restored.has("bytes")||!restored.get("bytes").isJsonNull())
            throw new AssertionError("Named native-control nulls were omitted");
        System.out.println("control JSON named/null and nested snapshot preservation passed");
    }
}
