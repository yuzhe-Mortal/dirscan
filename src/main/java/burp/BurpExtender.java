package burp;

import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.YamlReader;
import burp.Ui.Tags;
;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class BurpExtender implements IBurpExtender, IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private List<String> visitedUrls;  // 已访问的 URL 集合
    private List<String> newPaths;    // 从外部文件读取的新路径
    private YamlReader yamlReader;
    public static String NAME = "SensitiveDirScan";
    public static String VERSION = "1.0.1";
    private PrintWriter stdout;
    private Tags tags;
    private PrintWriter stderr;
    private ExecutorService executorService;
    private List<String> DirList;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.DirList = new ArrayList<>();
        this.visitedUrls = new ArrayList<>();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.yamlReader = YamlReader.getInstance(callbacks);
        callbacks.setExtensionName("DirScan");

        // 标签界面
        this.tags = new Tags(callbacks, NAME);


        // 从外部文件读取新路径
        newPaths = this.yamlReader.getStringList("scan.dir");

        this.stdout.println(basicInformationOutput());

        callbacks.registerHttpListener(this);
        this.executorService = Executors.newFixedThreadPool(10);
    }

    /**
     * 基本信息输出
     */
    private static String basicInformationOutput() {
        String str1 = "===================================\n";
        String str2 = String.format("%s Load the success\n", NAME);
        String str3 = String.format("VERSION: %s\n", VERSION);
        String str4 = "author: yuzhe\n";
        String str5 = "QQ: 3303003493\n";
        String str6 = "WeChat: a3303003493\n";
        String str7 = "GitHub: https://github.com/pmiaowu\n";
        String str8 = "Blog: https://www.yuque.com/pmiaowu\n";
        String str9 = String.format("downloadLink: %s\n", "https://github.com/pmiaowu/BurpShiroPassiveScan");
        String str10 = "===================================\n";
        String detail = str1 + str2 + str3 + str4 + str10;
        return detail;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 如果消息不是请求，直接返回
        if (messageIsRequest) {
            return;
        }
        String messageLevel = this.yamlReader.getString("messageLevel");
        List<String> KeyWords = this.yamlReader.getStringList("KeyWords");
        // 获取请求的 URL
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, messageInfo);
        IHttpRequestResponsePersisted message = callbacks.saveBuffersToTempFiles(messageInfo);
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        URL url = requestInfo.getUrl();
        String urlString = url.toString();

        if (!this.isUrlwhiteListSuffix(baseBurpUrl)) {
            return;
        }
        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return;
        }

        // 如果 URL 已经访问过，直接返回
        if (this.visitedUrls.contains(urlString)) {
            return;
        }

        // 将 URL 添加到已访问集合
        this.visitedUrls.add(urlString);

        int lastSlashIndex = url.getPath().lastIndexOf('/');
        String resourcePath = url.getPath().substring(lastSlashIndex + 1);

        for (String KewWord : KeyWords) {
            if (resourcePath.toLowerCase().contains(KewWord)) {
                this.stdout.println("[-]find KewWord:" + KewWord + "URL:" + urlString);
            }
        }

        // 递归访问上级目录
        String path = url.getPath();
        String UserUrl = new String();
        if (!path.equals("/")) {
            path = path.endsWith("/") ? path : path + "/";
            path = path.startsWith("/") ? path : "/" + path;
            String[] pathParts = path.split("/");
            //获取domain
            String IUrl = url.getProtocol() + "://" + url.getHost() + ":" + url.getPort();
            for (String dir : pathParts) {
                if (dir.contains("=")) {
                    continue;
                }
                if (messageLevel.equals("ALL") && !this.DirList.contains(dir)) {

                    this.DirList.add(dir);
                    this.stdout.println(dir);
                }
                IUrl = IUrl + "/" + dir;
                IUrl = IUrl.replaceAll("/$", "");
                for (String UserPath : newPaths) {
                    UserUrl = IUrl + "/" + UserPath;
                    IUrl = IUrl.replaceAll("/$", "");
                    try {
                        if (this.visitedUrls.contains(UserUrl)) {
                            continue;
                        }
                        this.visitedUrls.add(UserUrl);
                        URL parentUrl = new URL(UserUrl);
                        this.executorService.submit(() -> {
                            try {
                                reptile(messageInfo, parentUrl);
                            } catch (MalformedURLException e) {
                                e.printStackTrace();
                            }
                        });
                    } catch (Exception e) {
                        callbacks.printOutput("Error: " + e.getMessage());
                    }
                }
            }
        }
    }

    public void reptile(IHttpRequestResponse messageInfo, URL url) throws MalformedURLException {
        String Url = url.getPath();
        //test是排除误报请求
        String test = url.toString() + "/test_qaz_test";
        this.visitedUrls.add(test);

        List<String> headers = helpers.analyzeRequest(messageInfo.getRequest()).getHeaders();
        List<String> Testheaders = helpers.analyzeRequest(messageInfo.getRequest()).getHeaders();

        headers.set(0, "GET " + Url + " HTTP/1.1");
        Testheaders.set(0, "GET " + test + " HTTP/1.1");

        byte[] newRequest = helpers.buildHttpMessage(headers, null);
        byte[] TestNewRequest = helpers.buildHttpMessage(Testheaders, null);
        //发送请求
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(messageInfo.getHttpService(), newRequest);
        IHttpRequestResponse newHttpRequestResponseTest = callbacks.makeHttpRequest(messageInfo.getHttpService(), TestNewRequest);

        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(newHttpRequestResponse.getResponse());

        int bodyLength1 = newHttpRequestResponse.getResponse().length;
        int bodyLength2 = newHttpRequestResponseTest.getResponse().length;
        int responseStatusCode = responseInfo.getStatusCode();
        String contentType = responseInfo.getStatedMimeType();

        if ((responseStatusCode == 200) && bodyLength1 != bodyLength2 && bodyLength1 != 0) {
            if (contentType != null && (!contentType.toLowerCase().contains("jpeg") || !contentType.toLowerCase().contains("png"))) {
                this.tags.getScanQueueTagClass().add(
                        Url,
                        responseStatusCode + "",
                        bodyLength1 + "",
                        "Find Dir",
                        newHttpRequestResponse
                );
            }
        }
        return;
    }

    private boolean isUrlwhiteListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlWhiteListSuffix.config.isStart")) {
            return false;
        }
        String urlSuffix;
        String noParameterUrl = burpUrl.getRequestPath();
        int i = noParameterUrl.lastIndexOf(".");
        if (i == -1) {
            urlSuffix = "";
        } else {
            urlSuffix = noParameterUrl.substring(i + 1);
        }
        List<String> suffixList = this.yamlReader.getStringList("urlWhiteListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            new PrintWriter(callbacks.getStdout(), true).println();
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlBlackListSuffix.config.isStart")) {
            return false;
        }

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = this.yamlReader.getStringList("urlBlackListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

}

