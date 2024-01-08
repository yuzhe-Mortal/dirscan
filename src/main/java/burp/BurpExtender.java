package burp;

import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.YamlReader;
import burp.Ui.Tags;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender, IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private List<String> visitedUrls;  // 已访问的 URL 集合
    private List<Map<String, Object>> reptiles;    // 从外部文件读取的新路径
    private YamlReader yamlReader;
    public static String NAME = "DirScan";
    public static String VERSION = "1.2";
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
        this.reptiles = yamlReader.getMapList("reptile");

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
        ;
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
        List<String> domainNameBlacklist = this.yamlReader.getStringList("scan.domainName.blacklist");
        List<String> domainNameWhitelist = this.yamlReader.getStringList("scan.domainName.whitelist");
        String messageLevel = this.yamlReader.getString("messageLevel");
        List<String> KeyWords = this.yamlReader.getStringList("KeyWords");
        // 获取请求的 URL
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, messageInfo);
        IHttpRequestResponsePersisted message = callbacks.saveBuffersToTempFiles(messageInfo);
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        URL url = requestInfo.getUrl();
        String urlString = url.toString();

        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return;
            }
        }

        // 判断域名白名单
        if (domainNameWhitelist != null && domainNameWhitelist.size() >= 1) {
            if (!isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameWhitelist)) {
                return;
            }
        }

        // 判断当前请求后缀,是否为url白名单后缀
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
                for (Map<String, Object> reptile : reptiles) {
                    String name = (String) reptile.get("name");
                    List<String> paths = (List<String>) reptile.get("path");
                    String status = (String) reptile.get("status");
                    String regex = (String) reptile.get("regex");
                    for (String UserPath : paths) {
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
                                    reptile(messageInfo, name, parentUrl, status, regex);
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
    }

    public void reptile(IHttpRequestResponse messageInfo, String name, URL url, String status, String regex) throws MalformedURLException {
        //构建请求
        String Url = url.getPath();
        int StatusCode = 0;
        List<String> headers = helpers.analyzeRequest(messageInfo.getRequest()).getHeaders();
        headers.set(0, "GET " + Url + " HTTP/1.1");
        byte[] newRequest = helpers.buildHttpMessage(headers, null);
        IHttpRequestResponse newHttpRequestResponse = callbacks.makeHttpRequest(messageInfo.getHttpService(), newRequest);
        if (newHttpRequestResponse == null || newHttpRequestResponse.getResponse() == null) {
            return;
        }
        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(newHttpRequestResponse.getResponse());
        // 获取响应的body部分
        byte[] responseBody = Arrays.copyOfRange(newHttpRequestResponse.getResponse(), responseInfo.getBodyOffset(), newHttpRequestResponse.getResponse().length);

        String bodyAsString = new String(responseBody);
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(bodyAsString);
        if (!status.equals("")) {
            try {
                StatusCode = Integer.parseInt(status);
            } catch (NumberFormatException e) {
                StatusCode = 1;
            }
        } else {
            StatusCode = 1;
        }
        int bodyLength = responseBody.length;
        int responseStatusCode = responseInfo.getStatusCode();
        if (matcher.find() && (StatusCode == 1 || responseStatusCode == StatusCode) && bodyLength < 500000) {
            this.tags.getScanQueueTagClass().add(
                    Url,
                    responseStatusCode + "",
                    bodyLength + "",
                    name,
                    newHttpRequestResponse
            );
        }
        return;
    }

    private boolean isUrlwhiteListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlWhiteListSuffix.config.isStart")) {
            return true;
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

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }


}

