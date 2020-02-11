<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:dt="urn:schemas-microsoft-com:datatypes">
	<xsl:template match="//Process">
		<xsl:apply-templates>
			<xsl:sort select="./ParentProcessId" data-type="number" order="ascending"/>
			<xsl:sort select="./ProcessId" data-type="number" order="ascending"/>
		</xsl:apply-templates>
	</xsl:template>
	<xsl:template match="/">
		<html>
			<head>
				<title>Windows Process Connections</title></head>
			<style>
				.tableWrapper
                {
					width: 100%;
                    display: block;
					overflow: auto;
					position: relative;
				}

				table
                {
                    font-size: small;
					border: 1px solid black;
					border-collapse: collapse;
				}

				caption
                {
                    font-size: x-large;
					font-weight: bold;
					text-align: left;
				}

				th
                {
					border: 1px solid black;
					vertical-align: bottom;
					word-break: normal;
					overflow-wrap: normal;
				}

				td
                {
					border: 1px solid black;
					vertical-align: top;
				}

				td.wrapCell
                {
					word-break: break-word;
					overflow-wrap: break-word;
					white-space: normal;
				}

				td.noWrapCell
				{
					word-break: normal;
					overflow-wrap: normal;
					white-space: nowrap;
				}

                td.listCell
                {
					word-break: normal;
					overflow-wrap: normal;
					white-space: pre-line;
                }

				.processTable <xsl:text disable-output-escaping="yes"><![CDATA[>]]></xsl:text> thead
                {
					background-color: darkgray;
				}
				
				.processTable <xsl:text disable-output-escaping="yes"><![CDATA[>]]></xsl:text> tbody
                {
					border: 3px solid black;
				}
					
				.processTable <xsl:text disable-output-escaping="yes"><![CDATA[>]]></xsl:text> tbody:nth-child(even)
                {
					background-color: lightgray;
				}

				.networkAdapterTable th
                {
					background-color: darkgray;
				}
				
				.networkAdapterTable tr
                {
					border: 1px solid black;
				}
					
				.networkAdapterTable tr:nth-child(even)
                {
					background-color: lightgray;
				}

				.orphanTable th
                {
					background-color: darkgray;
				}
				
				.orphanTable tr
                {
					border: 1px solid black;
				}
					
				.orphanTable tr:nth-child(even)
                {
					background-color: lightgray;
				}
				
				.childTable
				{
					margin-left: 2em;
				}
				
				.childTable th
				{
					background-color: cadetblue
				}
				
				.childTable tr
				{
					border: 1px solid black;
				}

				.childTable tr:nth-child(even)
				{
					background-color: lightblue;
				}
			</style>
			<body>
				<h1>Windows Process Connections</h1>
                <div class="tableWrapper">
                    <table class="networkAdapterTable">
                        <thead>
                            <caption>Network Adapters</caption>
                            <tr>
                                <th>Interface Index</th>
                                <th>Service Name</th>
                                <th>Description</th>
                                <th>MAC Address</th>
                                <th>DHCP Enabled</th>
                                <th>DHCP Lease Obtained</th>
                                <th>DHCP Lease Expires</th>
                                <th>DHCP Server</th>
                                <th>IP Address</th>
                                <th>IP Subnet</th>
                                <th>Default IP Gateway</th>
                                <th>Full DNS Registration Enabled</th>
                                <th>DNS Hostname</th>
                                <th>DNS Domain</th>
                                <th>DNS Server Search Order</th>
                            </tr>
                        </thead>
                        <tbody>
                            <xsl:for-each select="//NetworkAdapter">
                                <tr>
 									<td><xsl:value-of select="./InterfaceIndex"/></td>
 									<td><xsl:value-of select="./ServiceName"/></td>
									<td><xsl:value-of select="./Description"/></td>
									<td><xsl:value-of select="./MACAddress"/></td>
									<td><xsl:value-of select="./DHCPEnabled"/></td>
                                    <td class="noWrapCell"><xsl:value-of select="ms:format-date(./DHCPLeaseObtained, 'yyyy-MM-dd')"/><xsl:text> </xsl:text><xsl:value-of select="ms:format-time(./DHCPLeaseObtained, 'HH:mm:ss')"/></td>
                                    <td class="noWrapCell"><xsl:value-of select="ms:format-date(./DHCPLeaseExpires, 'yyyy-MM-dd')"/><xsl:text> </xsl:text><xsl:value-of select="ms:format-time(./DHCPLeaseExpires, 'HH:mm:ss')"/></td>
									<td><xsl:value-of select="./DHCPServer"/></td>
									<td class="listCell"><xsl:value-of select="translate(normalize-space(./IPAddress), ' ', '&#x0A;')"/></td>
									<td class="listCell"><xsl:value-of select="translate(normalize-space(./IPSubnet), ' ', '&#x0A;')"/></td>
									<td class="listCell"><xsl:value-of select="translate(normalize-space(./DefaultIPGateway), ' ', '&#x0A;')"/></td>
									<td><xsl:value-of select="./FullDNSRegistrationEnabled"/></td>
									<td><xsl:value-of select="./DNSHostName"/></td>
									<td><xsl:value-of select="./DNSDomain"/></td>
									<td class="listCell"><xsl:value-of select="translate(normalize-space(./DNSServerSearchOrder), ' ', '&#x0A;')"/></td>
                                </tr>
                            </xsl:for-each>
                        </tbody>
                    </table>
                </div>
                <br/>
				<div class="tableWrapper">
					<table class="processTable">
                        <caption>Windows Processes</caption>
						<thead>
							<tr>
								<th>Process Id</th>
								<th>Parent Process Id</th>
								<th>Name</th>
								<th>Executable Path</th>
								<th>Command Line</th>
								<th>Owner</th>
								<th>Creation Date</th>
							</tr>
						</thead>
						<xsl:for-each select="//Process">
							<tbody>
								<tr>
									<td><xsl:value-of select="./ProcessId"/></td>
									<td><xsl:value-of select="./ParentProcessId"/></td>
									<td><xsl:value-of select="./Name"/></td>
									<td class="wrapCell"><xsl:value-of select="./ExecutablePath"/></td>
									<td class="wrapCell"><xsl:value-of select="./CommandLine"/></td>
									<td><xsl:value-of select="./Owner"/></td>
									<td class="noWrapCell"><xsl:value-of select="ms:format-date(./CreationDate, 'yyyy-MM-dd')"/><xsl:text> </xsl:text><xsl:value-of select="ms:format-time(./CreationDate, 'HH:mm:ss')"/></td>
								</tr>
								<xsl:if test="./TCPConnection">
									<tr>
										<td colspan="7">
											<div class="tableWrapper">
												<table class="childTable">
													<thead>
														<caption>TCP Connection(s)</caption>
														<tr>
															<th>Local Address Name</th>
															<th>Local Address</th>
															<th>Local Port</th>
															<th>Remote Address Name</th>
															<th>Remote Address</th>
															<th>Remote Port</th>
															<th>Status</th>
															<th>Creation Time</th>
														</tr>
													</thead>
													<tbody>
														<xsl:for-each select="./TCPConnection">
															<tr>
																<td><xsl:value-of select="./LocalAddressName"/></td>
																<td><xsl:value-of select="./LocalAddress"/></td>
																<td><xsl:value-of select="./LocalPort"/></td>
																<td><xsl:value-of select="./RemoteAddressName"/></td>
																<td><xsl:value-of select="./RemoteAddress"/></td>
																<td><xsl:value-of select="./RemotePort"/></td>
																<td><xsl:value-of select="./Status"/></td>
																<td class="noWrapCell"><xsl:value-of select="ms:format-date(./CreationTime, 'yyyy-MM-dd')"/><xsl:text> </xsl:text><xsl:value-of select="ms:format-time(./CreationTime, 'HH:mm:ss')"/></td>
															</tr>
														</xsl:for-each>
													</tbody>
												</table>
											</div>
										</td>						
									</tr>
								</xsl:if>
								<xsl:if test="./UDPEndpoint">
									<tr>
										<td colspan="7">
											<div class="tableWrapper">
												<table class="childTable">
													<thead>
														<caption>UDP Endpoint(s)</caption>
														<tr>
															<th>Local Address Name</th>
															<th>Local Address</th>
															<th>Local Port</th>
															<th>Creation Time</th>
														</tr>
													</thead>
													<tbody>
														<xsl:for-each select="./UDPEndpoint">
															<tr>
																<td><xsl:value-of select="./LocalAddressName"/></td>
																<td><xsl:value-of select="./LocalAddress"/></td>
																<td><xsl:value-of select="./LocalPort"/></td>
																<td class="noWrapCell"><xsl:if test="./CreationTime"><xsl:value-of select="ms:format-date(./CreationTime, 'yyyy-MM-dd')"/><xsl:text> </xsl:text><xsl:value-of select="ms:format-time(./CreationTime, 'HH:mm:ss')"/></xsl:if></td>
															</tr>
														</xsl:for-each>
													</tbody>
												</table>
											</div>
										</td>						
									</tr>
								</xsl:if>
								<xsl:if test="./Service">
									<tr>
										<td colspan="7">
											<div class="tableWrapper">
												<table class="childTable">
													<thead>
														<caption>Service(s)</caption>
														<tr>
															<th>Name</th>
															<th>Display Name</th>
															<th>Description</th>
															<th>Path Name</th>
															<th>Status</th>
														</tr>
													</thead>
													<tbody>
														<xsl:for-each select="./Service">
															<tr>
																<td><xsl:value-of select="./Name"/></td>
																<td><xsl:value-of select="./DisplayName"/></td>
																<td class="wrapCell"><xsl:value-of select="./Description"/></td>
																<td class="wrapCell"><xsl:value-of select="./PathName"/></td>
																<td><xsl:value-of select="./Status"/></td>
															</tr>
														</xsl:for-each>
													</tbody>
												</table>
											</div>
										</td>						
									</tr>
								</xsl:if>
							</tbody>
						</xsl:for-each>
					</table>
				</div>
				<xsl:if test="//OrphanTCPConnection">
                    <br/>
					<div class="tableWrapper">
						<table class="orphanTable">
							<thead>
								<caption>Orphan TCP Connection(s)</caption>
								<tr>
									<th>Owning Process</th>
									<th>Local Address Name</th>
									<th>Local Address</th>
									<th>Local Port</th>
									<th>Remote Address Name</th>
									<th>Remote Address</th>
									<th>Remote Port</th>
									<th>Status</th>
									<th>Creation Time</th>
								</tr>
							</thead>
							<tbody>
								<xsl:for-each select="//OrphanTCPConnection">
									<tr>
										<td><xsl:value-of select="./OwningProcess"/></td>
										<td><xsl:value-of select="./LocalAddressName"/></td>
										<td><xsl:value-of select="./LocalAddress"/></td>
										<td><xsl:value-of select="./LocalPort"/></td>
										<td><xsl:value-of select="./RemoteAddressName"/></td>
										<td><xsl:value-of select="./RemoteAddress"/></td>
										<td><xsl:value-of select="./RemotePort"/></td>
										<td><xsl:value-of select="./Status"/></td>
										<td class="noWrapCell"><xsl:value-of select="ms:format-date(./CreationTime, 'yyyy-MM-dd')"/><xsl:text> </xsl:text><xsl:value-of select="ms:format-time(./CreationTime, 'HH:mm:ss')"/></td>
									</tr>
								</xsl:for-each>
							</tbody>
						</table>
					</div>
 				</xsl:if>
				<xsl:if test="//OrphanUDPEndPoint">
                   <br/>
					<div class="tableWrapper">
						<table class="orphanTable">
							<thead>
								<caption>Orphan UDP Endpoint(s)</caption>
								<tr>
									<th>Owning Process</th>
									<th>Local Address Name</th>
									<th>Local Address</th>
									<th>Local Port</th>
									<th>Creation Time</th>
								</tr>
							</thead>
							<tbody>
								<xsl:for-each select="//OrphanUDPEndPoint">
									<tr>
										<td><xsl:value-of select="./OwningProcess"/></td>
										<td><xsl:value-of select="./LocalAddressName"/></td>
										<td><xsl:value-of select="./LocalAddress"/></td>
										<td><xsl:value-of select="./LocalPort"/></td>
										<td class="noWrapCell"><xsl:if test="./CreationTime"><xsl:value-of select="ms:format-date(./CreationTime, 'yyyy-MM-dd')"/><xsl:text> </xsl:text><xsl:value-of select="ms:format-time(./CreationTime, 'HH:mm:ss')"/></xsl:if></td>
									</tr>
								</xsl:for-each>
							</tbody>
						</table>
					</div>
				</xsl:if>
			</body>
		</html>
	</xsl:template>
</xsl:stylesheet>
