import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.json.JSONString;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import util.PGPDecryption;
import util.PGPEncryption;
import util.PGPKeyUtil;
import org.springframework.beans.factory.annotation.Value;

import java.nio.charset.Charset;
import java.util.*;

@SpringBootApplication
@ComponentScan
public class Main {
    @Value("${pass.phrase}")
    private static String injectedPassphrase;

    private static String STATIC_NAME;

    @Value("${pass.phrase}")
    public void setStaticName(String name) {
        STATIC_NAME = name;
    }

    public static String getStaticName() {
        return STATIC_NAME;
    }

    public static void main(String[] args) throws Exception {

        System.out.println(getStaticName());

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("username", "chisom.odoemelam");
        requestBody.put("password", "sx[+M29467Fe");
        ObjectMapper objectMapper = new ObjectMapper();
        String json = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(requestBody);
        System.out.println(json);
        String re = "{\"username\":\"chisom.odoemelam\",\"password\":\"sx[+M29467Fe\"}";

        final String encryptedCredentials = new String(PGPEncryption.encrypt(re.getBytes(Charset.defaultCharset())));
        System.out.println(encryptedCredentials);




//        System.out.println(jsonObject.get("password"));
        String string =  "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG C# v1.9.0.0\n" +
                "\n" +
                "hQEMA02Rh89V02rgAQf/UsjaE5JYUa1VgLO06GyrbtcUY7v5GVPo+ZlFd7wCUbED\n" +
                "6BLJ07IHNDzdnHY29JyWnO8u6RsPiQHX+hGAfh34GjdA4DYAgxHYAS4RQW2W9rtB\n" +
                "AEJb90N1hlWIKZlVyZdGI6CT87XNHTONqW+OhO17LjZDWEjr9sMjA6YJac9Wry+5\n" +
                "k4vRH5dQwewQsfNKgxlUaR3FUkgv5m00BajnLbxCwcwkxL9+JbVDO/kbZdHr4qTQ\n" +
                "IQOm2bSDXHOyLWTiLwkwaKdPL3k474QtzEpl0B2TIvwyHOrElxGxmzqQ6cfO9M+Q\n" +
                "U592kt/NDQLbD79OS7m4KaIaHlZ9bh3mS4NUym2wsNKdAS9NXrFT9Vof1HMjCnzr\n" +
                "39YV3LM0kPnwdglOYovbqeF0sKLWS75t4xrd6BW3EvY3o+e+wgMdnWjwlGZRn6XZ\n" +
                "GkJTFaK80+Omges7Sv3jZrqZVZRu1fMVJSIxPqaxZLvPoduOTQKrdtSjUaW41Zf6\n" +
                "wBPoS8mMi4iErbma615/Tq+ozP21Q8vQbUGVMzuU1IXtj10tFDMrnXUY9OV98Q==\n" +
                "=jD2a\n" +
                "-----END PGP MESSAGE-----";
        String decryptedResponse = new String(PGPDecryption.decrypt(string.getBytes()));
        System.out.println(decryptedResponse);
        JSONObject jsonObject = new JSONObject(decryptedResponse);
        System.out.println(jsonObject);
        System.out.println(jsonObject.getString("ResponseCode"));
        Map<String, String> map = new HashMap<>();
        map.put("data", string);
        String son = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
        System.out.println(son);

    }
}
