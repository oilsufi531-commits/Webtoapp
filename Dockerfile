FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV GRADLE_HOME=/opt/gradle/gradle-8.9
ENV PATH=/usr/lib/jvm/java-17-openjdk-amd64/bin:/opt/gradle/gradle-8.9/bin:/usr/local/bin:/usr/bin:/bin

RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jdk-headless unzip zip curl ca-certificates procps && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/android-sdk/cmdline-tools
RUN curl -fsSL -o /tmp/cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
RUN unzip -q /tmp/cmdline-tools.zip -d /opt/android-sdk/cmdline-tools
RUN mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest
RUN rm -f /tmp/cmdline-tools.zip

RUN yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses > /dev/null 2>&1 || true
RUN /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"

RUN curl -fsSL -o /tmp/gradle.zip https://services.gradle.org/distributions/gradle-8.9-bin.zip
RUN mkdir -p /opt/gradle
RUN unzip -q /tmp/gradle.zip -d /opt/gradle
RUN rm -f /tmp/gradle.zip

RUN mkdir -p /var/lib/androidbuildworker
RUN chmod 700 /var/lib/androidbuildworker

WORKDIR /app
COPY package.json ./
COPY server.js ./

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["node", "server.js"]
