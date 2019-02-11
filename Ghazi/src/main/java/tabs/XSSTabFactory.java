package tabs;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IParameter;
import burp.IRequestInfo;
import burp.ITextEditor;

public class XSSTabFactory implements IMessageEditorTabFactory{

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
    private PrintWriter stdout;
	
	
    public XSSTabFactory(IBurpExtenderCallbacks callbacks) {
    	this.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new XSSTab(controller, editable);
    }
	
	class XSSTab implements IMessageEditorTab{
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        public XSSTab(IMessageEditorController controller, boolean editable)
        {
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //

        @Override
        public String getTabCaption()
        {
            return "XSS";
        }

        @Override
        public Component getUiComponent()
        {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest)
        {
        	return isRequest;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                txtInput.setText(null);
                txtInput.setEditable(false);
            }else{
                IRequestInfo reqInfo = helpers.analyzeRequest(content);
                List<IParameter> params = reqInfo.getParameters();
                byte paramType = reqInfo.getMethod().equals("GET")? IParameter.PARAM_URL : IParameter.PARAM_BODY;
                
                // xss payloads
                String xssStart = "\"/><script>alert(";
                String xssEnd = ");</script>";
                int num = 1;
                for(int i=0; i < params.size(); i++) {
                	IParameter param = params.get(i);
                	if(param.getType() != IParameter.PARAM_COOKIE && !param.getName().contains("_csrf")) {
                		IParameter newParam = helpers.buildParameter(
            						param.getName(), 
            						xssStart + (num++) + xssEnd,  //payload
            						paramType);
	                	content = helpers.updateParameter(content, newParam);
	                	//stdout.println("parameter [" + param.getName() + "]'s value setted to " + newParam.getValue());
                	}
                }
                txtInput.setText(content);
                txtInput.setEditable(editable);
            }
            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage()
        {
        	return currentMessage;
        }

        @Override
        public boolean isModified()
        {
        	return false; //always
        }

        @Override
        public byte[] getSelectedData()
        {
            return txtInput.getSelectedText();
        }
    }
}