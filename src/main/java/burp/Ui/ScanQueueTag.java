package burp.Ui;

import burp.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ScanQueueTag extends AbstractTableModel implements IMessageEditorController {

    private JSplitPane mjSplitPane;
    private List<TablesData> Udatas = new ArrayList<TablesData>();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private URLTable Utable;
    private JScrollPane UscrollPane;
    private JSplitPane HjSplitPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;

    public ScanQueueTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
        JPanel scanQueue = new JPanel(new BorderLayout());

        // 主分隔面板
        mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mjSplitPane.setResizeWeight(0);

        // 任务栏面板
        Utable = new URLTable(ScanQueueTag.this);
//        添加滚动条
        UscrollPane = new JScrollPane(Utable);

        // 请求与响应界面的分隔面板规则
        HjSplitPane = new JSplitPane();
        HjSplitPane.setResizeWeight(0.5);

        // 请求的面板
        Ltable = new JTabbedPane();
        HRequestTextEditor = callbacks.createMessageEditor(ScanQueueTag.this, false);
        Ltable.addTab("Request", HRequestTextEditor.getComponent());

        // 响应的面板
        Rtable = new JTabbedPane();
        HResponseTextEditor = callbacks.createMessageEditor(ScanQueueTag.this, false);
        Rtable.addTab("Response", HResponseTextEditor.getComponent());

        // 自定义程序UI组件
        HjSplitPane.add(Ltable, "left");
        HjSplitPane.add(Rtable, "right");

        mjSplitPane.add(UscrollPane, "left");
        mjSplitPane.add(HjSplitPane, "right");

        scanQueue.add(mjSplitPane);
        tabs.addTab("扫描队列", scanQueue);
    }
    //设置request,response面板调用方法
    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }
//设置任务栏面板调用方法
//    设置行数
    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
//    设置列数
    public int getColumnCount() {
        return 6;
    }
//    设置字段名称
    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "ID";
            case 1:
                return "url";
            case 2:
                return "statusCode";
            case 3:
                return "Length";
            case 4:
                return "issue";
            case 5:
                return "startTime";
        }
        return null;
    }
//    获取字段类型
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }
//    获取字段值
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.id;
            case 1:
                return datas.url;
            case 2:
                return datas.statusCode;
            case 3:
                return datas.Length;
            case 4:
                return datas.issue;
            case 5:
                return datas.startTime;
        }
        return null;
    }

    /**
     * 新增任务至任务栏面板
     *
     * @param url
     * @param statusCode
     * @param Length
     * @param issue
     * @param requestResponse
     * @return int id
     */
    public int add(String url, String statusCode, String Length,
                   String issue,
                   IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String startTime = sdf.format(d);

            int id = this.Udatas.size();
            this.Udatas.add(
                    new TablesData(
                            id,
                            url,
                            statusCode,
                            Length,
                            issue,
                            startTime,
                            requestResponse
                    )
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }

    /**
     * 更新任务状态至任务栏面板
     *
     * @param id
     * @param url
     * @param statusCode
     * @param Length
     * @param issue
     * @param requestResponse

     * @return int id
     */
    public int save(int id, String url, String statusCode,
                    String Length, String issue,
                    IHttpRequestResponse requestResponse) {
        TablesData dataEntry = ScanQueueTag.this.Udatas.get(id);
        String startTime = dataEntry.startTime;

        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String endTime = sdf.format(d);

        synchronized (this.Udatas) {
            this.Udatas.set(
                    id,
                    new TablesData(
                            id,
                            url,
                            statusCode,
                            Length,
                            issue,
                            startTime,
                            requestResponse
                    )
            );
            fireTableRowsUpdated(id, id);
            return id;
        }
    }

    /**
     * 自定义Table
     */
    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = ScanQueueTag.this.Udatas.get(convertRowIndexToModel(row));
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     * 界面显示数据存储模块
     */
    private static class TablesData {
        final int id;
        final String url;
        final String statusCode;
        final String Length;
        final String issue;
        final String startTime;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id, String url, String statusCode,
                          String Length, String issue,  String startTime,
                          IHttpRequestResponse requestResponse) {
            this.id = id;
            this.url = url;
            this.statusCode = statusCode;
            this.Length= Length;
            this.issue = issue;
            this.startTime = startTime;
            this.requestResponse = requestResponse;
        }
    }
}