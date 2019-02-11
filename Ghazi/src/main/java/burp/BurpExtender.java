package burp;

import java.io.PrintWriter;

import tabs.SQLTabFactory;
import tabs.XSSTabFactory;
import tabs.RCETabFactory;
import tabs.LFITabFactory;
import tabs.SSRFTabFactory;
import tabs.SSTITabFactory;
import tabs.BXSSTabFactory;

public class BurpExtender implements IBurpExtender{

	private XSSTabFactory factory1;
	private SQLTabFactory factory2;
	private RCETabFactory factory3;
	private LFITabFactory factory4;
	private SSRFTabFactory factory5;
	private SSTITabFactory factory6;
	private BXSSTabFactory factory7;
	
	
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
    	
        callbacks.setExtensionName("Ghazi 1.1");
        factory1 = new XSSTabFactory(callbacks);
        factory2 = new SQLTabFactory(callbacks);
        factory3 = new RCETabFactory(callbacks);
        factory4 = new LFITabFactory(callbacks);
        factory5 = new SSRFTabFactory(callbacks);
        factory6 = new SSTITabFactory(callbacks);
        factory7 = new BXSSTabFactory(callbacks);
        callbacks.registerMessageEditorTabFactory(factory1);
        callbacks.registerMessageEditorTabFactory(factory2);
        callbacks.registerMessageEditorTabFactory(factory3);
        callbacks.registerMessageEditorTabFactory(factory4);
        callbacks.registerMessageEditorTabFactory(factory5);
        callbacks.registerMessageEditorTabFactory(factory6);
        callbacks.registerMessageEditorTabFactory(factory7);
        
        stdout.println("Thank You For Using Ghazi 1.1");
        stdout.println("Contributors:\n\tKazam Chaudhary (twitter.com/p3n73st3r)\n\tKashif Hussain\n\tIjaz Ur Rahim fb\\MisterDebugger");
        stdout.println("Installation complete.");
    }

   
}