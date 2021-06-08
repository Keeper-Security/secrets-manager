package internal;

import com.keepersecurity.secretsManager.core.SecretsManagerKt;

public class App {
    public String getGreeting() {
        return "Hello world.";
    }

    public static void main(String[] args) {
        if (SecretsManagerKt.doSomethingElse()) {
            System.out.println(new App().getGreeting());
        }
    }
}
