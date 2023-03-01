package burp.Ui;

import burp.Bootstrap.YamlReader;
import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;

public class BaseSettingTag {
    private YamlReader yamlReader;

    private JCheckBox isStartBox;

    public BaseSettingTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs, YamlReader yamlReader) {
        JPanel baseSetting = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        this.yamlReader = yamlReader;

        this.input1_1(baseSetting, c);
        this.input1_2(baseSetting, c);

        tabs.addTab("插件基础设置", baseSetting);
    }

    private void input1_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_1_1 = new JLabel("内容");
        br_lbl_1_1.setForeground(new Color(255, 89, 18));
        br_lbl_1_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_1_1.getFont().getSize() + 2));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 0;
        baseSetting.add(br_lbl_1_1, c);
    }

    private void input1_2(JPanel baseSetting, GridBagConstraints c) {
//        定义标签类型为按钮
        this.isStartBox = new JCheckBox("插件状态：启动", this.yamlReader.getBoolean("isStart"));
//        定义位置
        this.isStartBox.setFont(new Font("Serif", Font.PLAIN, this.isStartBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 1;
        baseSetting.add(this.isStartBox, c);
    }

    public Boolean isStart() {
        return this.isStartBox.isSelected();
    }
}