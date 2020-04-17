import sys
import csv
import datetime
import dateutil.parser as date_parse
import xml.etree.ElementTree as ET
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pyad.adquery
import pyad.aduser
import os
import shutil

def quarantine_file(file_path, destination, has_owner, inc_details = {}):
    '''
    File is relocated from original directory to destination directory and a text file is left in the original directory with instructions.

    *file_path: current file location
    *destination: where file is to be moved
    
    '''
    TODAY = datetime.date.today().isoformat()

    # checks for existing file with the same name in the quarantine directory
    if not os.path.exists(destination):
        try:
            shutil.move(file_path, destination)
            moved = True
        except:
            moved = False
    else:
        # renames file in standard windows format i.e. filename(1).txt
        try:
            file_name_only = os.path.splitext(os.path.basename(destination))[0]
            file_extension = os.path.splitext(os.path.basename(destination))[1]
            directory_path = os.path.splitext(destination)[0][:destination.rfind("\\")]
            new_full_path = destination
            increment_counter = 1

            while os.path.exists(new_full_path):
                temp_file_name = "%s(%s)" %(file_name_only, str(increment_counter))
                new_full_path = os.path.join(directory_path, temp_file_name + file_extension)
                increment_counter += 1
            
            destination = new_full_path

            shutil.move(file_path, destination)
            
            moved = True
        except:
            moved = False
    
    if moved:
        now = datetime.datetime.now().strftime('%x %X')
        file_name = os.path.basename(file_path)
        file_directory = os.path.splitext(file_path)[0][:file_path.rfind("\\")]
        
        send_notification(has_owner, inc_details)

        tombstone = open("%s\\%s.txt" %(file_directory, file_name), "w+")
        tombstone.write("This file has been quarantined as it potentially contains sensitive data that violates corporate policy.  If you would like to request restoration of the file please refer to the Elavon Data at Rest Remediation FAQ (URL below). \n \n Date Quarantined: %s \n Incident ID: %s \n File Directory: %s \n File Name: %s \n File Expiration Date: %s \n\n https://connections.us.bank-dns.com/communities/service/html/communityview?communityUuid=15ad2889-134a-4ac0-b4ca-634801f5d124#fullpageWidgetId=Wc4a6fd12ceb2_451e_9054_3d7efe1529fc&file=3ef080f1-f090-4a5c-98a4-4c0683af99c3" %(now, inc_details['incidentID'], inc_details['folderpath'], inc_details['filename'], inc_details['deletionDate']))
        tombstone.close()
        
        #set log location based on destination server
        if "KNXSZDATA01" in destination:
            log_path = "\\\\SVPKNXSZDATA01\\Quarantine\\Logs\\%s\\quarantine_log.csv" %(TODAY)
        elif "CTYSZDATA01" in destination:
            log_path = "\\\\SVPCTYSZDATA01\\Quarantine\\Logs\\%s\\quarantine_log.csv" %(TODAY)
        else:
			log_path = "\\\\svpknxdfsr01\\departments\\_Anyshare\\GIS-DLP\\DAR Warning Campaign\\Logs\\%s\\quarantine_log.csv" %(TODAY)
        
        #create log directory if it does not exist
        if not os.path.exists(os.path.splitext(log_path)[0][:log_path.rfind("\\")]):
            os.makedirs(os.path.splitext(log_path)[0][:log_path.rfind("\\")])
        
        #initialize log column headers if new file
        if not os.path.exists(log_path):
            move_log = open("%s" %(log_path), "a+")
            move_log.write("Date Quarantined,Original File Path,Original File Directory,Original File Name,Quarantine File Path\n")
            move_log.close()
        
        #write log data to file
        move_log = open("%s" %(log_path), "a+")
        move_log.write("%s,%s,%s,%s,%s\n" %(TODAY, file_path, file_directory, file_name, destination))
        move_log.close()

    return moved

def send_notification(has_owner, inc_details = {}):
    '''
    Text or HTML email is sent depending on recipient's email client.  Incident detail inputs are referenced in email template string.
    Additional user metadata is added from a query to AD based on the user ID input.  All inputs are obtained from incident XML file.

    *has_owner: Boolean flag used to control email contents and recipient depending on if the file has an owner or not
    *inc_details: Dictionary of values obtained either from the incident XML or from AD resolution

    '''
    # Email gateway
    SMTPGATEWAY="mailrelay.global.prv"
    text = ""
    html = ""
    no_owner_text = ""
    no_owner_html = ""

    if has_owner:
        # text version of email for clients that do not support HTML
        text = """\
            ForcePoint
            DLP

            Date: %s

            Your file was identifed as high risk due to having an excessive amount of unsecured Personal Information (Credit Card Numbers, Credit Card Track Data, or SSNs) contained within the content, which is a violation of Information Security policy.
            The file has been quarantined and will be deleted 90 days from the date of this notice.
            
            You may request your file be restored; however, the file, or the Personal Information within the file, must be secured according to policy.  
            To request your file be restored, open a ticket within ServiceNow and attach this email to the ticket.
            Please note, the SLA for file recovery is 2 business days.
                                        
            Please refer to page 5 of the Elavon Data Loss Prevention (DLP) Controls FAQ for details on how to properly secure data within network storage: 
            https://connections.us.bank-dns.com/communities/service/html/communityview?communityUuid=15ad2889-134a-4ac0-b4ca-634801f5d124#fullpageWidgetId=Wc4a6fd12ceb2_451e_9054_3d7efe1529fc&file=b6610834-f387-4279-88c1-f6b7d3e0ca2b

            
            Incident Details: 

            ID: %s
            Severity: %s
            Action: Warning
            Maximum Matches: %s
            Date Last Accessed: %s
            Date Last Modified: %s
            Analyzed By: %s

            Source:
            
            Full name: %s
            Login name: %s
            Manager name: %s
            Phone number: %s
            Title: %s
            Department: %s
            File Path: %s
            
            Violation triggers:
            Rule(s): %s
            > Classifier(s): %s
        """ % (
            inc_details['detectDate'],
            inc_details['incidentID'],
            inc_details['severity'],
            inc_details['matches'],
            inc_details['accessedDate'],
            inc_details['modifiedDate'],
            inc_details['analyzedBy'],
            inc_details['userName'],
            inc_details['userID'],
            inc_details['userMgr'], 
            inc_details['userPhone'],
            inc_details['userTitle'],
            inc_details['userDept'],
            inc_details['filepath'], 
            inc_details['rules'],
            inc_details['classifiers']
            )

        #html version of email
        html = """\
            <html xmlns:fn="http://www.w3.org/2005/02/xpath-functions">
            <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <meta http-equiv="PRAGMA" content="NO-CACHE">
            <meta http-equiv="EXPIRES" content="-1">
            <meta http-equiv="CACHE-CONTROL" content="NO-CACHE">
            <title>Websense</title>
            <style type="text/css">
                    body {
                        margin : 0px;
                        scrollbar-base-color : #97A4BE;
                        scrollbar-arrow-color : #959DA8;
                        scrollbar-face-color : #D4DCE3;
                        scrollbar-highlight-color : #D4DCE3;
                        scrollbar-shadow-color : #D4DCE3;
                        scrollbar-track-color: #E2EBF2;
                        scrollbar-3dlight-color : #959DA8;
                        scrollbar-darkshadow-color : #959DA8;
                    }

                    body, td, a, div, span, label, input, select, textarea{
                        font-family : Tahoma, Verdana, Arial, Helvetica, sans-serif;
                        font-size : 11px;
                        color: black;
                    }

                    .ppExtraPaddingBottom {
                        padding-bottom: 5px;
                        margin-bottom: 5px;
                    }

                    .ppExtraPaddingTop {
                        padding-top: 5px;
                        margin-top: 5px;
                    }
                    
                    .ppExtraPaddingTop2 {
                        padding-top: 10px;
                        margin-top: 5px;
                    }	
                    
                    .ppExtraPaddingTopLeft {
                        padding-top: 5px;
                        margin-top: 5px;
                        padding-left: 5px;
                    }	
                    
                    .ppExtra2PaddingTopLeft {
                        padding-top: 10px;
                        margin-top: 10px;
                        padding-left: 5px;
                    }	
                    
                    .ppExtraPaddingTopLeftRight {
                        padding-top: 5px;
                        margin-top: 5px;
                        padding-left: 5px;
                        padding-right: 5px;
                    }	
                    
                    .ppExtraPaddingRight {
                        padding-right: 15px;
                        margin-right: 5px;
                    }
                    
                    .ppDisplayBlockFloatLeft {
                        display: block; 
                        float: left;
                    }

                    .ppWhiteText {
                        color: white;
                        padding-left: 5px;
                        vertical-align: top;
                    }
                    
                    .ppReportLine{
                        padding-top: 2px;
                        padding-left: 5px;
                    }

                    .ppReportLineText{
                        padding-left: 5px;
                    }

                    .ppReportTitleText{
                        font-family : Arial Caps, Arial, Helvetica, sans-serif;
                        font-size : 14px;
                        font-weight: bold;
                        color: #0F3451;
                        padding-top: 8px;
                        padding-left: 5px;
                        padding-bottom: 0px;
                        border-bottom: 1px solid #96A1AE;
                        width: 100%%;
                    }

                    .ppIncidentsTableContainer {
                        width: 100%%;
                    }

                    .eventDetailsContainer{
                        margin-top: 10px;
                    }

                    .ppIncidentDetailsTableTop {
                        background-image: url(images/printing/table-top.gif);
                        background-repeat: no-repeat;
                        width: 100%%;
                        vertical-align: top;
                    }

                    .ppIncidentDetailsTableTopText {
                        color: white;
                        padding-left: 10px;
                        vertical-align: top;
                        text-decoration: none;
                    }

                    .ppIncidentDetailsTableData {
                        width: 100%%;
                        vertical-align: top;
                    }

                    .ppIncidentDetailsTableDataInnerTable {
                        border: 1px solid #96A1AE;
                        padding-left: 5px;
                        padding-right: 5px;
                        padding-top: 2px;
                        padding-bottom: 2px;
                    }

                    .ppInnerTablePlaceHolder {
                        text-align: left;
                    }
                    
                    .ppInnerTablePlaceHolderLeft {
                        text-align: left;
                        padding-left: 5px;
                    }

                    .ppTextDesc{
                        font-weight: bold;
                        vertical-align: top;
                        white-space: nowrap;
                    }
                    
                    .ppUnderlineText {
                        text-decoration:underline;
                    }
                    
                    .ppTextDescSmall{
                        font-weight: bold;
                        vertical-align: top;
                        white-space: nowrap;
                    }
                    
                    td.ppTextInfoLength {
                        width: 300px;
                    }

                    td.ppTextDesc {
                        width: 120px;
                    }
                                
                    td.ppTextDescSmall {
                        width: 70px;
                        
                    }

                    .ppTextInfo{
                        vertical-align: top;
                        padding-right: 50px;
                    }

                    .ppTextInfoSource{
                        vertical-align: top;
                    }
                
                    .ppSubReportTableTitle {
                        width: 100%%;
                        padding-bottom: 2px;
                    }

                    .ppSubReportTitleText {
                        font-size : 12px;
                        color: #0F3451;
                    }

                    .regularTextColNoBorder{
                        padding-left:5px;
                        padding-right:5px;
                        white-space : nowrap;
                        text-align: left;
                        vertical-align: top;
                    }
                    
                    .ppIconText {
                        text-indent: 10px;
                        padding-right:10px;
                        text-align:left;
                    }
                    
                    .colorBlue {
                        color : blue;
                        white-space: nowrap;
                    }
                    
                    .colorGray {
                        color : gray;
                        white-space: nowrap;
                    }

                    
                    .brightBG {
                        background-color : #ECF4FB;
                    }
                    
                    .darkBg {
                        background-color : #D4DCE3;
                    }
                    
                    .nowrapTd {
                        white-space: nowrap;
                    }
                                                        
                    .alignLeft100{
                        text-align:-moz-left;
                        text-align:-khtml-left;
                        _text-align:left;
                        width: 100%%;
                    }
                    
                    .alignLeft100Padding{
                        text-align:-moz-left;
                        text-align:-khtml-left;
                        _text-align:left;
                        width: 100%%;
                        padding-left: 2px;
                    }
                                
                    .severityIcon {				 			
                        font-weight: bold;
                        color: white;	
                        text-align: center;	
                        width: 15px;
                    }

                    .sup {
                        font-size: 60%%;
                        vertical-align: top;
                    }
                    .visibilityHidden {
                        display: none;	
                    }
                </style>
            </head>
            <body>
                <table border="0" cellpadding="0" cellspacing="0" width="100%%">
                <tbody>
                    <tr>
                        <td style="color:#43b02a;"><h2>FORCEPOINT</h2></td>
                    </tr>
                    <tr>
                        <td style="color:#000000;"><h3>DLP</h3></td>
                    </tr>
                    <tr>
                        <td>
                            <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td class="ppReportTitleText" colspan="2">&nbsp;</td>
                                </tr>
                                <tr class="ppReportLine">
                                    <td style="white-space: nowrap;">Date:</td><td class="ppReportLineText" style="width:100%%">%s</td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText" colspan="2"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table class="" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr class="ppExtraPaddingTop">
                                    <td class="ppWhiteText"></td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table class="" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr class="ppExtraPaddingTop">
                                    <td class="ppWhiteText"></td>
                                </tr>
                                <tr>
                                    <td class="ppReportTitleText">Message to user</td>
                                </tr>
                                <tr class="ppReportLine">
                                    <td>
                                        <p>
                                    The file listed below was identified as containing high risk, unsecured Personal Information (Credit Card Numbers, Credit Card Track Data, SSNs), which is a violation of Information Security policy.
                                    <br>
                                    The file has been quarantined and will be deleted on %s.
                                    <br>
									<br>
                                    Refer to the table below to determine if any action is necessary.
                                    <br><br>
                                    </p>
                                        <table style='border-collapse:collapse;border:none;mso-border-alt:solid windowtext .5pt;mso-yfti-tbllook:1184;mso-padding-alt:0in 5.4pt 0in 5.4pt'>
                                            <tr style='mso-yfti-irow:0;mso-yfti-firstrow:yes'>
                                                <td width=156 valign=top style='width:117.35pt;border:solid windowtext 1.0pt;mso-border-alt:solid windowtext .5pt;padding:0in 5.4pt 0in 5.4pt'>
													<p>
														<b style='mso-bidi-font-weight:normal'>
															<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>Scenario<o:p></o:p></span>
														</b>
													</p>
												</td>
                                                <td width=306 valign=top style='width:229.5pt;border:solid windowtext 1.0pt;border-left:none;mso-border-left-alt:solid windowtext .5pt;mso-border-alt:solid windowtext .5pt;padding:0in 5.4pt 0in 5.4pt'>
													<p>
														<b style='mso-bidi-font-weight:normal'>
															<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>Action<o:p></o:p></span>
														</b>
													</p>
												</td>
                                            </tr>
                                            <tr>
                                                <td width=156 style='width:117.35pt;border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:solid windowtext .5pt;mso-border-alt:solid windowtext .5pt;padding:0in 5.4pt 0in 5.4pt;height:51.25pt'>
													<p align=center style='text-align:center'>
														<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>The file is still needed<o:p></o:p></span>
													</p>
												</td>
                                                <td width=306 valign=top style='width:229.5pt;border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .5pt;mso-border-left-alt:solid windowtext .5pt;mso-border-alt:solid windowtext .5pt;padding:0in 5.4pt 0in 5.4pt;height:51.25pt'>
													<p>
														<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>The file will need to be restored by submitting a restoration request within ServiceNow.  Please note the SLA for file recovery is 2 business days.<o:p></o:p></span>
													</p>
                                                    <p>
														<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>Once the file is restored it will need to be secured in ONE of these ways:<o:p></o:p></span>
													</p>
													<p style='margin-left:.5in;margin-bottom:0em;text-indent:-.25in;mso-list:l0 level1 lfo1'>
														<![if !supportLists]>
															<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;mso-fareast-font-family:Tahoma;color:black'>
																<span style='mso-list:Ignore'>1.
																	<span style='font:7.0pt "Times New Roman"'>&nbsp;&nbsp;&nbsp;&nbsp;</span>
																</span>
															</span>
														<![endif]>
														<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>Delete or Sanitize sensitive data within the file.<o:p></o:p></span>
													</p>
													<p style='margin-left:.5in;margin-top:0em;text-indent:-.25in;mso-list:l0 level1 lfo1'>
														<![if !supportLists]>
															<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;mso-fareast-font-family:Tahoma;color:black'>
																<span style='mso-list:Ignore'>2.
																	<span style='font:7.0pt "Times New Roman"'>&nbsp;&nbsp;&nbsp;&nbsp;</span>
																</span>
															</span>
														<![endif]>
														<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>Encrypt file (<a href="https://connections.us.bank-dns.com/communities/service/html/communityview?communityUuid=15ad2889-134a-4ac0-b4ca-634801f5d124#fullpageWidgetId=Wc4a6fd12ceb2_451e_9054_3d7efe1529fc&file=0bcca5e0-4698-4b32-a6ca-966d39156477">Voltage SecureFile</a>).<o:p></o:p></span>
													</p>
												</td>
                                            </tr>
                                            <tr>
                                                <td width=156 style='width:117.35pt;border:solid windowtext 1.0pt;border-top:none;mso-border-top-alt:solid windowtext .5pt;mso-border-alt:solid windowtext .5pt;padding:0in 5.4pt 0in 5.4pt'>
													<p align=center style='text-align:center'>
														<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>The file is no longer needed<o:p></o:p></span>
													</p>
												</td>
                                                <td width=306 valign=top style='width:229.5pt;border-top:none;border-left:none;border-bottom:solid windowtext 1.0pt;border-right:solid windowtext 1.0pt;mso-border-top-alt:solid windowtext .5pt;mso-border-left-alt:solid windowtext .5pt;mso-border-alt:solid windowtext .5pt;padding:0in 5.4pt 0in 5.4pt'>
													<p>
														<span style='font-size:8.5pt;font-family:"Tahoma",sans-serif;color:black'>No action is required and no further notices pertaining to this file will be received.  The file will be deleted on %s.<o:p></o:p></span>
													</p>
												</td>
                                            </tr>
                                        </table>
                                    <br>
									<p>
                                    Please review the <a href=https://connections.us.bank-dns.com/communities/service/html/communityview?communityUuid=15ad2889-134a-4ac0-b4ca-634801f5d124#fullpageWidgetId=Wc4a6fd12ceb2_451e_9054_3d7efe1529fc&file=59994c92-01fc-47af-9e2d-f0476107a569>Elavon Data at Rest Remediation FAQ</a> for how to submit a request to have a file released from quarantine.
                                    </p> 
                                    </td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table class="" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr class="ppExtraPaddingTop">
                                    <td class="ppWhiteText"></td>
                                </tr>
                                <tr>
                                    <td class="ppReportTitleText">Incident details</td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table id="incidents" border="0" cellpadding="0" cellspacing="0" class="ppIncidentsTableContainer">
                                <tr>
                                    <td>
                                        <table class="eventDetailsContainer" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                            <tr class="ppIncidentDetailsTableData">
                                                <td>
                                                    <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                        <tr class="ppInnerTablePlaceHolderLeft">
                                                            <td>
                                                                <table border="0" cellpadding="0" cellspacing="0">
                                                                    <tr>
                                                                        <td class="ppTextDesc">ID:</td><td class="ppTextInfo">%s</td>
                                                                        <td class="ppTextDescSmall">Incident time:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDescSmall">Severity:</td><td class="ppTextInfo">%s</td>
                                                                        <td class="ppTextDesc">Maximum matches:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Status:</td><td class="ppTextInfo ppTextInfoLength">Warning</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Date Last Accessed:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Date Last Modified:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Analyzed By:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                </table>
                                                            </td>
                                                        </tr>
                                                        <tr class="ppInnerTablePlaceHolderLeft">
                                                            <td class="ppExtraPaddingTop">
                                                                <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                                    <tr>
                                                                        <td>
                                                                            <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                                                <tr>
                                                                                    <td class="ppTextDesc">Source:</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfoSource">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr>
                                                                                                <td class="ppIconText">Full name:</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                    <td class="ppTextInfoSource">%s*</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfoSource">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr>
                                                                                                <td class="ppIconText">Login name:</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                    <td class="ppTextInfoSource">%s</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfoSource">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr>
                                                                                                <td class="ppIconText">Manager name:</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                    <td class="ppTextInfoSource">%s*</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfoSource">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr>
                                                                                                <td class="ppIconText">Phone number:</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                    <td class="ppTextInfoSource">%s*</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfoSource">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr>
                                                                                                <td class="ppIconText">Title: </td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                    <td class="ppTextInfoSource">%s*</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfoSource">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr>
                                                                                                <td class="ppIconText">Department:</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                    <td class="ppTextInfoSource">%s*</td>
                                                                                </tr>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                    <tr class="ppInnerTablePlaceHolderLeft">
                                                                        <td class="ppExtraPaddingTop">
                                                                            <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                                                <tr>
                                                                                    <td>
                                                                                        <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                                                            <tr style="height: 10px;">
                                                                                                * This was not one of the incident's original properties. It was determined through user name resolution via Active Directory.  
                                                                                                <br>
                                                                                                Updates to this information can be submitted here: <a href="http://directoryupdate/Login.aspx">Directory Update</a>
                                                                                                <br>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                </tr>
                                                                                <tr class="ppInnerTablePlaceHolderLeft">
                                                                                    <td class="ppExtraPaddingTop">
                                                                                        <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                                                        </table>
                                                                                    </td>
                                                                                </tr>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                </table>
                                                                <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                    <tr class="ppRowTextDesc">
                                                                        <td class="ppTextInfo" style="width: 120px;">
                                                                            <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                <tr>
                                                                                    <td class="ppTextDesc">Folder Path:</td>
                                                                                    <td class="ppTextInfo"><a href=%s>%s</a></td>
                                                                                </tr>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                    <tr class="ppRowTextDesc">
                                                                    <td class="ppTextInfo" style="width: 120px;">
                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                            <tr>
                                                                                <td class="ppTextDesc">Tombstone File:</td>
                                                                                <td class="ppTextInfo">%s</td>
                                                                            </tr>
                                                                        </table>
                                                                    </td>
                                                                </tr>
                                                                    <tr class="ppRowTextDesc">
                                                                        <td class="ppTextInfo" style="width: 120px;">
                                                                            <table class="ppInnerTablePlaceholder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                <tr>
                                                                                    <td class="ppTextDesc">Violation triggers:</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfo">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr class="ppRowTextDesc">
                                                                                                <td class="ppTextInfo" style="width: 120px;">
                                                                                                    <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                                        <tr>
                                                                                                            <td></td><td class="ppIconText">Rule:</td>
                                                                                                        </tr>
                                                                                                    </table>
                                                                                                </td>
                                                                                                <td class="ppTextInfo">%s</td>
                                                                                            </tr>
                                                                                            <tr class="ppRowTextDesc">
                                                                                                <td class="ppTextInfo" style="width: 120px;">
                                                                                                    <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                                        <tr>
                                                                                                            <td></td><td class="ppIconText">Classifier:</td>
                                                                                                        </tr>
                                                                                                    </table>
                                                                                                </td>
                                                                                                <td class="ppTextInfo">%s</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfo">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr class="ppRowTextDesc">
                                                                                                <td class="ppTextInfo" style="width: 120px;">
                                                                                                    <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                                        <tr>
                                                                                                            <td style="padding-right: 0px;"></td><td class="ppIconText">Matches:</td>
                                                                                                        </tr>
                                                                                                    </table>
                                                                                                </td>
                                                                                                <td class="ppTextInfo">%s</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                </tr>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                </table>
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td class="ppExtraPaddingBottom"><span class="ppWhiteText"></span></td>
                    </tr>
                </tbody>
                </table>
            </body>
            </html>
        """ % (
            inc_details['detectDate'],
            inc_details['deletionDate'],
            inc_details['deletionDate'],
            inc_details['incidentID'],
            inc_details['detectDate'],
            inc_details['severity'],
            inc_details['matches'],
            inc_details['accessedDate'],
            inc_details['modifiedDate'],
            inc_details['analyzedBy'],
            inc_details['userName'],
            inc_details['userID'],
            inc_details['userMgr'], 
            inc_details['userPhone'],
            inc_details['userTitle'],
            inc_details['userDept'], 
            '"' + inc_details['folderpath'] + '"', 
            inc_details['folderpath'],
            inc_details['filename'] + ".txt",
            inc_details['rules'],
            inc_details['classifiers'],
            inc_details['matchedData']
            )
    
        msg = MIMEMultipart('Alternative')
        msg['Subject'] = 'NOTICE: Your file has been quarantined'
        msg['From'] = "DLP-Admin-Quarantine@elavon.com"
        msg['To'] = userEmail

        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")

        msg.attach(part1)
        msg.attach(part2)

        if userMgrEmail == "unknown":
            toEmail = [userEmail, "ISSDCPEngEA@elavon.com"]
        else:
            toEmail = [userEmail, userMgrEmail, "ISSDCPEngEA@elavon.com"]
            msg['CC'] = userMgrEmail
    else:
        #text version of email for clients that do not support HTML
        no_owner_text = """\
            ForcePoint
            DLP

            Date: %s

            This file was identifed as having unsecured Personal Information (Credit Card Numbers, Credit Card Track Data, or SSNs) contained within the content, which is a violation of Information Security policy.
            The file has no identifiable owner so it has been quarantined and will be deleted 90 days from the date of this notice.

            Incident Details: 

            ID: %s
            Severity: %s
            Action: Warning
            Maximum Matches: %s
            Date Last Accessed: %s
            Date Last Modified: %s
            Analyzed By: %s

            Source:
            
            ID: %s
            
            File Path: %s
            
            Violation triggers:
            Rule(s): %s
            > Classifier(s): %s
        """ % (
            inc_details['detectDate'],
            inc_details['incidentID'],
            inc_details['severity'],
            inc_details['matches'],
            inc_details['accessedDate'],
            inc_details['modifiedDate'],
            inc_details['analyzedBy'],
            inc_details['userID'],
            inc_details['filepath'], 
            inc_details['rules'],
            inc_details['classifiers']
            )

        #html version of email
        no_owner_html = """\
            <html xmlns:fn="http://www.w3.org/2005/02/xpath-functions">
            <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <meta http-equiv="PRAGMA" content="NO-CACHE">
            <meta http-equiv="EXPIRES" content="-1">
            <meta http-equiv="CACHE-CONTROL" content="NO-CACHE">
            <title>Websense</title>
            <style type="text/css">
                    body {
                        margin : 0px;
                        scrollbar-base-color : #97A4BE;
                        scrollbar-arrow-color : #959DA8;
                        scrollbar-face-color : #D4DCE3;
                        scrollbar-highlight-color : #D4DCE3;
                        scrollbar-shadow-color : #D4DCE3;
                        scrollbar-track-color: #E2EBF2;
                        scrollbar-3dlight-color : #959DA8;
                        scrollbar-darkshadow-color : #959DA8;
                    }

                    body, td, a, div, span, label, input, select, textarea{
                        font-family : Tahoma, Verdana, Arial, Helvetica, sans-serif;
                        font-size : 11px;
                        color: black;
                    }

                    .ppExtraPaddingBottom {
                        padding-bottom: 5px;
                        margin-bottom: 5px;
                    }

                    .ppExtraPaddingTop {
                        padding-top: 5px;
                        margin-top: 5px;
                    }
                    
                    .ppExtraPaddingTop2 {
                        padding-top: 10px;
                        margin-top: 5px;
                    }	
                    
                    .ppExtraPaddingTopLeft {
                        padding-top: 5px;
                        margin-top: 5px;
                        padding-left: 5px;
                    }	
                    
                    .ppExtra2PaddingTopLeft {
                        padding-top: 10px;
                        margin-top: 10px;
                        padding-left: 5px;
                    }	
                    
                    .ppExtraPaddingTopLeftRight {
                        padding-top: 5px;
                        margin-top: 5px;
                        padding-left: 5px;
                        padding-right: 5px;
                    }	
                    
                    .ppExtraPaddingRight {
                        padding-right: 15px;
                        margin-right: 5px;
                    }
                    
                    .ppDisplayBlockFloatLeft {
                        display: block; 
                        float: left;
                    }

                    .ppWhiteText {
                        color: white;
                        padding-left: 5px;
                        vertical-align: top;
                    }
                    
                    .ppReportLine{
                        padding-top: 2px;
                        padding-left: 5px;
                    }

                    .ppReportLineText{
                        padding-left: 5px;
                    }

                    .ppReportTitleText{
                        font-family : Arial Caps, Arial, Helvetica, sans-serif;
                        font-size : 14px;
                        font-weight: bold;
                        color: #0F3451;
                        padding-top: 8px;
                        padding-left: 5px;
                        padding-bottom: 0px;
                        border-bottom: 1px solid #96A1AE;
                        width: 100%%;
                    }

                    .ppIncidentsTableContainer {
                        width: 100%%;
                    }

                    .eventDetailsContainer{
                        margin-top: 10px;
                    }

                    .ppIncidentDetailsTableTop {
                        background-image: url(images/printing/table-top.gif);
                        background-repeat: no-repeat;
                        width: 100%%;
                        vertical-align: top;
                    }

                    .ppIncidentDetailsTableTopText {
                        color: white;
                        padding-left: 10px;
                        vertical-align: top;
                        text-decoration: none;
                    }

                    .ppIncidentDetailsTableData {
                        width: 100%%;
                        vertical-align: top;
                    }

                    .ppIncidentDetailsTableDataInnerTable {
                        border: 1px solid #96A1AE;
                        padding-left: 5px;
                        padding-right: 5px;
                        padding-top: 2px;
                        padding-bottom: 2px;
                    }

                    .ppInnerTablePlaceHolder {
                        text-align: left;
                    }
                    
                    .ppInnerTablePlaceHolderLeft {
                        text-align: left;
                        padding-left: 5px;
                    }

                    .ppTextDesc{
                        font-weight: bold;
                        vertical-align: top;
                        white-space: nowrap;
                    }
                    
                    .ppUnderlineText {
                        text-decoration:underline;
                    }
                    
                    .ppTextDescSmall{
                        font-weight: bold;
                        vertical-align: top;
                        white-space: nowrap;
                    }
                    
                    td.ppTextInfoLength {
                        width: 300px;
                    }

                    td.ppTextDesc {
                        width: 120px;
                    }
                                
                    td.ppTextDescSmall {
                        width: 70px;
                        
                    }

                    .ppTextInfo{
                        vertical-align: top;
                        padding-right: 50px;
                    }

                    .ppTextInfoSource{
                        vertical-align: top;
                    }
                
                    .ppSubReportTableTitle {
                        width: 100%%;
                        padding-bottom: 2px;
                    }

                    .ppSubReportTitleText {
                        font-size : 12px;
                        color: #0F3451;
                    }

                    .regularTextColNoBorder{
                        padding-left:5px;
                        padding-right:5px;
                        white-space : nowrap;
                        text-align: left;
                        vertical-align: top;
                    }
                    
                    .ppIconText {
                        text-indent: 10px;
                        padding-right:10px;
                        text-align:left;
                    }
                    
                    .colorBlue {
                        color : blue;
                        white-space: nowrap;
                    }
                    
                    .colorGray {
                        color : gray;
                        white-space: nowrap;
                    }

                    
                    .brightBG {
                        background-color : #ECF4FB;
                    }
                    
                    .darkBg {
                        background-color : #D4DCE3;
                    }
                    
                    .nowrapTd {
                        white-space: nowrap;
                    }
                                                        
                    .alignLeft100{
                        text-align:-moz-left;
                        text-align:-khtml-left;
                        _text-align:left;
                        width: 100%%;
                    }
                    
                    .alignLeft100Padding{
                        text-align:-moz-left;
                        text-align:-khtml-left;
                        _text-align:left;
                        width: 100%%;
                        padding-left: 2px;
                    }
                                
                    .severityIcon {				 			
                        font-weight: bold;
                        color: white;	
                        text-align: center;	
                        width: 15px;
                    }

                    .sup {
                        font-size: 60%%;
                        vertical-align: top;
                    }
                    .visibilityHidden {
                        display: none;	
                    }
                </style>
            </head>
            <body>
                <table border="0" cellpadding="0" cellspacing="0" width="100%%">
                <tbody>
                    <tr>
                        <td style="color:#43b02a;"><h2>FORCEPOINT</h2></td>
                    </tr>
                    <tr>
                        <td style="color:#000000;"><h3>DLP</h3></td>
                    </tr>
                    <tr>
                        <td>
                            <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td class="ppReportTitleText" colspan="2">&nbsp;</td>
                                </tr>
                                <tr class="ppReportLine">
                                    <td style="white-space: nowrap;">Date:</td><td class="ppReportLineText" style="width:100%%">%s</td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText" colspan="2"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table class="" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr class="ppExtraPaddingTop">
                                    <td class="ppWhiteText"></td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table class="" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr class="ppExtraPaddingTop">
                                    <td class="ppWhiteText"></td>
                                </tr>
                                <tr>
                                    <td class="ppReportTitleText">Message to user</td>
                                </tr>
                                <tr class="ppReportLine">
                                    <td>
                                        <p>
                                        This file was identifed as having unsecured Personal Information (Credit Card Numbers, Credit Card Track Data, or SSNs) contained within the content, which is a violation of Information Security policy.
                                        <br>
                                        The file has no identifiable owner so it has been quarantined and will be deleted 90 days from the date of this notice.
                                        </p>
                                    </td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table class="" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                <tr class="ppExtraPaddingTop">
                                    <td class="ppWhiteText"></td>
                                </tr>
                                <tr>
                                    <td class="ppReportTitleText">Incident details</td>
                                </tr>
                                <tr class="ppExtraPaddingBottom">
                                    <td class="ppWhiteText"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <table id="incidents" border="0" cellpadding="0" cellspacing="0" class="ppIncidentsTableContainer">
                                <tr>
                                    <td>
                                        <table class="eventDetailsContainer" width="100%%" border="0" cellpadding="0" cellspacing="0">
                                            <tr class="ppIncidentDetailsTableData">
                                                <td>
                                                    <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                        <tr class="ppInnerTablePlaceHolderLeft">
                                                            <td>
                                                                <table border="0" cellpadding="0" cellspacing="0">
                                                                    <tr>
                                                                        <td class="ppTextDesc">ID:</td><td class="ppTextInfo">%s</td>
                                                                        <td class="ppTextDescSmall">Incident time:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDescSmall">Severity:</td><td class="ppTextInfo">%s</td>
                                                                        <td class="ppTextDesc">Maximum matches:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Status:</td><td class="ppTextInfo ppTextInfoLength">Warning</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Date Last Accessed:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Date Last Modified:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td class="ppTextDesc">Analyzed By:</td><td class="ppTextInfo">%s</td>
                                                                    </tr>
                                                                </table>
                                                            </td>
                                                        </tr>
                                                        <tr class="ppInnerTablePlaceHolderLeft">
                                                            <td class="ppExtraPaddingTop">
                                                                <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                                    <tr>
                                                                        <td>
                                                                            <table width="100%%" border="0" cellpadding="0" cellspacing="0">
                                                                                <tr>
                                                                                    <td class="ppTextDesc">Source:</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfoSource">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr>
                                                                                                <td class="ppIconText">ID:</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                    <td class="ppTextInfoSource">%s</td>
                                                                                </tr>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                </table>
                                                                <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                    <tr class="ppRowTextDesc">
                                                                        <td class="ppTextInfo" style="width: 120px;">
                                                                            <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                <tr>
                                                                                    <td class="ppTextDesc">File Path:</td>
                                                                                    <td class="ppTextInfo">%s</td>
                                                                                </tr>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                    <tr class="ppRowTextDesc">
                                                                        <td class="ppTextInfo" style="width: 120px;">
                                                                            <table class="ppInnerTablePlaceholder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                <tr>
                                                                                    <td class="ppTextDesc">Violation triggers:</td>
                                                                                </tr>
                                                                                <tr class="ppRowTextDesc">
                                                                                <tr class="ppRowTextDesc">
                                                                                    <td class="ppTextInfo">
                                                                                        <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                            <tr class="ppRowTextDesc">
                                                                                                <td class="ppTextInfo" style="width: 120px;">
                                                                                                    <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                                        <tr>
                                                                                                            <td></td><td class="ppIconText">Rule:</td>
                                                                                                        </tr>
                                                                                                    </table>
                                                                                                </td>
                                                                                                <td class="ppTextInfo">%s</td>
                                                                                            </tr>
                                                                                            <tr class="ppRowTextDesc">
                                                                                                <td class="ppTextInfo" style="width: 120px;">
                                                                                                    <table class="ppInnerTablePlaceHolder" cellspacing="0" cellpadding="0" border="0" width="100%%">
                                                                                                        <tr>
                                                                                                            <td style="width: 25px;"></td><td class="ppIconText">Classifier:</td>
                                                                                                        </tr>
                                                                                                    </table>
                                                                                                </td>
                                                                                                <td class="ppTextInfo">%s</td>
                                                                                            </tr>
                                                                                        </table>
                                                                                    </td>
                                                                                </tr>
                                                                            </table>
                                                                        </td>
                                                                    </tr>
                                                                </table>
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td class="ppExtraPaddingBottom"><span class="ppWhiteText"></span></td>
                    </tr>
                </tbody>
                </table>
            </body>
            </html>
        """ % (
            inc_details['detectDate'],
            inc_details['incidentID'],
            inc_details['detectDate'],
            inc_details['severity'],
            inc_details['matches'],
            inc_details['accessedDate'],
            inc_details['modifiedDate'],
            inc_details['analyzedBy'],
            inc_details['userID'],
            inc_details['filepath'][2:], 
            inc_details['rules'],
            inc_details['classifiers']
            )

        msg = MIMEMultipart('Alternative')
        msg['Subject'] = 'NOTICE: A file has been quarantined'
        msg['From'] = "DLP-Admin-Quarantine@elavon.com"
        msg['To'] = "DLP-Admin@elavon.com"

        part1 = MIMEText(no_owner_text, "plain")
        part2 = MIMEText(no_owner_html, "html")

        msg.attach(part1)
        msg.attach(part2)

        toEmail = "ISSDCPEngEA@elavon.com"

    # send email message
    mail = smtplib.SMTP(SMTPGATEWAY)
    mail.sendmail("ISSDCPEngEA@elavon.com", toEmail, msg.as_string())
    mail = None

# XML search path constants
NS1=u".//{http://www.portauthoritytech.com/schmea/xml-rpc/1.0}"
EVT=u".//{http://www.portauthoritytech.com/schmea/incident/1.0}"
EVTDETECTDATE=EVT+u'localDetectedTime'
EVTINCIDENT=EVT+u"incidentId"
EVTMATCHCOUNT=EVT+u'numOfMatches'
EVTFILE=EVT+u'file'
EVTOWNER=EVT+u"detail"
EVTUSER=EVT+u"incidentUser"
EVTFILEPATH=EVT+u"path"
EVTRULE=EVT+u'rule'
EVTMATCHEDDATA=EVT+u'masked'
EVTDATEACCESSED=EVT+u'dateAccessed'
EVTDATEMODIFIED=EVT+u'dateModified'
EVTRESOURCETYPE=EVT+u'resourceType'
EVTANALYZEDBY=EVT+u'analyzedBy'

TODAY = datetime.date.today().isoformat()

DELETION_DATE = (datetime.date.today() + datetime.timedelta(days=90)).strftime('%b %d, %Y')

# Parse the XML file
oXMLTree=ET.parse(sys.argv[1])

# Import XML values into dictionary
dIncidentDetails={}
rule_ids = []
rule_names = []
classifier_names = []
num_matches = []
matched_data = []

na_locations = ['KNX', 'ATL', 'DEN', 'LAR', 'ONT', 'MEX' 'TOR', 'PLS', 'QTR']
eu_locations = ['IXN', 'CTY', 'WAT', 'LON', 'MAD', 'SVRFRA', 'SVROSL']

for elem in oXMLTree.findall(EVTRULE):
    rule_ids.append(elem.get('id'))

for elem in oXMLTree.findall(EVTMATCHCOUNT):
    num_matches.append(int(elem.text))

for elem in oXMLTree.findall(EVTMATCHEDDATA):
    if len(matched_data) >= 50:
        break
    else:
        matched_data.append(elem.text)

# Import XML values into dictionary

dIncidentDetails['detectDate']=date_parse.parse(oXMLTree.find(EVTDETECTDATE).text).strftime('%m/%d/%Y %H:%M:%S')
dIncidentDetails['incidentID']=oXMLTree.find(EVTINCIDENT).text
dIncidentDetails['matches']=max(num_matches)
dIncidentDetails['userID']=oXMLTree.find(EVTOWNER).get('value')
dIncidentDetails['filepath']=oXMLTree.find(EVTFILEPATH).text
dIncidentDetails['accessedDate']=date_parse.parse(oXMLTree.find(EVTDATEACCESSED).text)
dIncidentDetails['modifiedDate']=date_parse.parse(oXMLTree.find(EVTDATEMODIFIED).text)
dIncidentDetails['scanType']=oXMLTree.find(EVTRESOURCETYPE).text
dIncidentDetails['analyzedBy']=oXMLTree.find(EVTANALYZEDBY).text
dIncidentDetails['deletionDate']=DELETION_DATE

share_assoc_location = "\\\\na\\departments\\knoxville\\_Anyshare\\ForcePoint\\ShareEnum\\sharelist.csv"

share_assoc_file = open(share_assoc_location, "r")
data = csv.reader(share_assoc_file)

for row in data:
    admin_share = row[2].replace(":", "$").upper()

    if admin_share.upper() in dIncidentDetails['filepath'].upper():
        old_path = dIncidentDetails['filepath'].upper()

        if admin_share == "K$\\KNOXVILLE\\DEPARTMENTS":
            new_path = old_path.replace(admin_share, "KnoxvilleDept").lower()
        elif admin_share == "F$\\ATLANTA\\DEPARTMENTS":
            new_path = old_path.replace(admin_share, "AtlantaDept").lower()
        else:
            new_path = old_path.replace(admin_share, row[1]).lower()
		
        dIncidentDetails['folderpath'] = os.path.dirname(new_path)
        dIncidentDetails['filename'] = os.path.basename(new_path)
        break

share_assoc_file.close()

if not 'folderpath' in dIncidentDetails:
	dIncidentDetails['folderpath'] = os.path.dirname(dIncidentDetails['filepath'])
	dIncidentDetails['filename'] = os.path.basename(dIncidentDetails['filepath'])

match_count = int(dIncidentDetails['matches'])

# Determine severity based on match count
if match_count >= 1000:
    dIncidentDetails['severity'] = "Critical"
elif match_count >= 100 or match_count < 999:
    dIncidentDetails['severity'] = "High"
elif match_count >= 50 or match_count < 99:
    dIncidentDetails['severity'] = "Medium"
else:
    dIncidentDetails['severity'] = "Low"

# Determine Data Element Matched based on rule ID - PROD
for rule_id in rule_ids:
    if rule_id == '18484':
        classifier_names.append('Credit Card Number with CVV')
        rule_names.append('PCI Audit: CCN and CVV')
    elif rule_id == '18483':
        classifier_names.append("Credit Card Number with Exp Date")
        rule_names.append('PCI Audit: CCN and Expiration Date')
    elif rule_id == '18488':
        classifier_names.append("Credit Card Magnetic Strip Data")
        rule_names.append('PCI Audit: Credit Card Magnetic Strip')
    elif rule_id == '18487':
        classifier_names.append('Credit Card Number')
        rule_names.append('PCI Audit: Credit Card Number (Default)')
    elif rule_id == '18794':
        classifier_names.append('Social Security Number')
        rule_names.append('US PII: SSN Narrow')

dIncidentDetails['rules'] = ', '.join(rule_names)
dIncidentDetails['classifiers'] = ', '.join(classifier_names)
dIncidentDetails['matchedData'] = ', '.join(matched_data)

trimmed_user_id = dIncidentDetails['userID'][3:]
converted_accessed_date = dIncidentDetails['accessedDate'].strftime('%m/%d/%Y %H:%M:%S')

# initialize user info variables
distinguished_name = ""
region = ""
userEmail = ""
userName = ""
userMgrDn = ""
userMgrName = ""
userMgrEmail = ""
userPhone = ""
userTitle = ""
userDept = ""
sendMail = True
keep_going = True

if not dIncidentDetails['scanType'] == 'NETWORK':
    keep_going = False

if keep_going:
    
    for loc in na_locations:
        if loc in dIncidentDetails['filepath'].upper():
            region = 'North America'

    for loc in eu_locations:
        if loc in dIncidentDetails['filepath'].upper():
            region = 'Europe'

    if 'NA\\' in dIncidentDetails['userID'] or 'EU\\' in dIncidentDetails['userID']:

        q = pyad.adquery.ADQuery()

        if dIncidentDetails['userID'][:2] == "NA":
            pyad.adquery.set_defaults(ldap_server="na.global.prv")
            distinguished_name = "DC=na,DC=global,DC=prv"
        elif dIncidentDetails['userID'][:2] == "EU":
            pyad.adquery.set_defaults(ldap_server="eu.global.prv")
            distinguished_name = "DC=eu,DC=global,DC=prv"

        #query AD for user information
        try:
            q.execute_query(
                attributes=["sAMAccountName", "mail", "name", "telephoneNumber", "title", "department", "manager"], 
                where_clause = "sAMAccountName = '%s'" %(trimmed_user_id),
                base_dn="%s" %(distinguished_name))

            for row in q.get_results():
                if row['sAMAccountName'] == trimmed_user_id:
                    userEmail = row['mail']
                    userName = row['name']

                    if row['manager'] != None:
                        userMgrDn = row['manager']
                    else:
                        userMgr = ""

                    userPhone = row['telephoneNumber']
                    userDept = row['department']
                    userTitle = row['title']
        except:
            userEmail = 'unknown'   

        #query AD for user's manager information if populated
        try:
            if not userMgrDn == "":
                q.execute_query(attributes=["mail", "name"], where_clause= "distinguishedName = '%s'" %(userMgrDn), base_dn="%s" %(distinguished_name))

                for row in q.get_results():
                    userMgrEmail = row['mail']
                    userMgrName = row['name']
            else:
                userMgrEmail = 'unknown'
                userMgrName = 'unknown'
        except:
            userMgrEmail = 'unknown'

        #do nothing if no user information is available
        if userEmail == 'unknown' or userEmail == "":
            sendMail = False

        dIncidentDetails['userName'] = userName
        dIncidentDetails['userMgr'] = userMgrName
        dIncidentDetails['userPhone'] = userPhone
        dIncidentDetails['userTitle'] = userTitle
        dIncidentDetails['userDept'] = userDept

        if region == "North America":
            quarantine_path = "\\\\SVPKNXSZDATA01\\Quarantine\\Automated\\%s\\%s" %(trimmed_user_id, TODAY)
        elif region == "Europe":
            quarantine_path = "\\\\SVPCTYSZDATA01\\Quarantine\\Automated\\%s\\%s" %(trimmed_user_id, TODAY)
        else:
            quarantine_path = ""

        source = dIncidentDetails['filepath']

        if not quarantine_path == "":
            if not os.path.exists(quarantine_path):
                os.makedirs(quarantine_path)
            
            quarantine_file(source, os.path.join(quarantine_path, os.path.basename(source)), sendMail, dIncidentDetails)
    else:
        if region == "North America":
            quarantine_path = "\\\\SVPKNXSZDATA01\\Quarantine\\Automated\\Administrator\\%s" %(TODAY)
        elif region == "Europe":
            quarantine_path = "\\\\SVPCTYSZDATA01\\Quarantine\\Automated\\Administrator\\%s" %(TODAY)
        else:
            quarantine_path = ""

        source = dIncidentDetails['filepath']

        if not quarantine_path == "":
            if not os.path.exists(quarantine_path):
                os.makedirs(quarantine_path)
                
            quarantine_file(source, os.path.join(quarantine_path, os.path.basename(source)), False, dIncidentDetails)

