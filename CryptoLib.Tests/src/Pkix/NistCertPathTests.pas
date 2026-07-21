{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit NistCertPathTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  PkitsTestBase;

type
  /// <summary>
  /// The NIST Public Key Interoperability Test Suite path validation cases, run against the
  /// certification path validator of RFC 5280 6.1.
  /// </summary>
  TNistCertPathTest = class(TPkitsTestCase)
  published
    /// <summary>4.1.1 Valid Signatures Test1</summary>
    procedure Test4_1_1;
    /// <summary>4.1.2 Invalid CA Signature Test2</summary>
    procedure Test4_1_2;
    /// <summary>4.1.3 Invalid EE Signature Test3</summary>
    procedure Test4_1_3;
    /// <summary>4.1.4 Valid DSA Signatures Test4</summary>
    procedure Test4_1_4;
    /// <summary>4.1.5 Valid DSA Parameter Inheritance Test5</summary>
    procedure Test4_1_5;
    /// <summary>4.1.6 Invalid DSA Signature Test6</summary>
    procedure Test4_1_6;
    /// <summary>4.2.1 Invalid CA notBefore Date Test1</summary>
    procedure Test4_2_1;
    /// <summary>4.2.2 Invalid EE notBefore Date Test2</summary>
    procedure Test4_2_2;
    /// <summary>4.2.3 Valid pre2000 UTC notBefore Date Test3</summary>
    procedure Test4_2_3;
    /// <summary>4.2.4 Valid GeneralizedTime notBefore Date Test4</summary>
    procedure Test4_2_4;
    /// <summary>4.2.5 Invalid CA notAfter Date Test5</summary>
    procedure Test4_2_5;
    /// <summary>4.2.6 Invalid EE notAfter Date Test6</summary>
    procedure Test4_2_6;
    /// <summary>4.2.7 Invalid pre2000 UTC EE notAfter Date Test7</summary>
    procedure Test4_2_7;
    /// <summary>4.2.8 Valid GeneralizedTime notAfter Date Test8</summary>
    procedure Test4_2_8;
    /// <summary>4.3.1 Invalid Name Chaining EE Test1</summary>
    procedure Test4_3_1;
    /// <summary>4.3.2 Invalid Name Chaining Order Test2</summary>
    procedure Test4_3_2;
    /// <summary>4.3.3 Valid Name Chaining Whitespace Test3</summary>
    procedure Test4_3_3;
    /// <summary>4.3.4 Valid Name Chaining Whitespace Test4</summary>
    procedure Test4_3_4;
    /// <summary>4.3.5 Valid Name Chaining Capitalization Test5</summary>
    procedure Test4_3_5;
    /// <summary>4.3.6 Valid Name Chaining UIDs Test6</summary>
    procedure Test4_3_6;
    /// <summary>4.3.7 Valid RFC3280 Mandatory Attribute Types Test7</summary>
    procedure Test4_3_7;
    /// <summary>4.3.8 Valid RFC3280 Optional Attribute Types Test8</summary>
    procedure Test4_3_8;
    /// <summary>4.3.9 Valid UTF8String Encoded Names Test9</summary>
    procedure Test4_3_9;
    /// <summary>4.3.10 Valid Rollover from PrintableString to UTF8String Test10</summary>
    procedure Test4_3_10;
    /// <summary>4.3.11 Valid UTF8String Case Insensitive Match Test11</summary>
    procedure Test4_3_11;
    /// <summary>4.4.1 Missing CRL Test1</summary>
    procedure Test4_4_1;
    /// <summary>4.4.2 Invalid Revoked CA Test2</summary>
    procedure Test4_4_2;
    /// <summary>4.4.3 Invalid Revoked EE Test3</summary>
    procedure Test4_4_3;
    /// <summary>4.4.4 Invalid Bad CRL Signature Test4</summary>
    procedure Test4_4_4;
    /// <summary>4.4.5 Invalid Bad CRL Issuer Name Test5</summary>
    procedure Test4_4_5;
    /// <summary>4.4.6 Invalid Wrong CRL Test6</summary>
    procedure Test4_4_6;
    /// <summary>4.4.7 Valid Two CRLs Test7</summary>
    procedure Test4_4_7;
    /// <summary>4.4.8 Invalid Unknown CRL Entry Extension Test8</summary>
    procedure Test4_4_8;
    /// <summary>4.4.9 Invalid Unknown CRL Extension Test9</summary>
    procedure Test4_4_9;
    /// <summary>4.4.10 Invalid Unknown CRL Extension Test10</summary>
    procedure Test4_4_10;
    /// <summary>4.4.11 Invalid Old CRL nextUpdate Test11</summary>
    procedure Test4_4_11;
    /// <summary>4.4.12 Invalid pre2000 CRL nextUpdate Test12</summary>
    procedure Test4_4_12;
    /// <summary>4.4.13 Valid GeneralizedTime CRL nextUpdate Test13</summary>
    procedure Test4_4_13;
    /// <summary>4.4.14 Valid Negative Serial Number Test14</summary>
    procedure Test4_4_14;
    /// <summary>4.4.15 Invalid Negative Serial Number Test15</summary>
    procedure Test4_4_15;
    /// <summary>4.4.16 Valid Long Serial Number Test16</summary>
    procedure Test4_4_16;
    /// <summary>4.4.17 Valid Long Serial Number Test17</summary>
    procedure Test4_4_17;
    /// <summary>4.4.18 Invalid Long Serial Number Test18</summary>
    procedure Test4_4_18;
    /// <summary>4.4.19 Valid Separate Certificate and CRL Keys Test19</summary>
    procedure Test4_4_19;
    /// <summary>4.4.20 Invalid Separate Certificate and CRL Keys Test20</summary>
    procedure Test4_4_20;
    /// <summary>4.4.21 Invalid Separate Certificate and CRL Keys Test21</summary>
    procedure Test4_4_21;
    /// <summary>4.5.1 Valid Basic Self-Issued Old With New Test1</summary>
    procedure Test4_5_1;
    /// <summary>4.5.2 Invalid Basic Self-Issued Old With New Test2</summary>
    procedure Test4_5_2;
    /// <summary>4.5.3 Valid Basic Self-Issued New With Old Test3</summary>
    procedure Test4_5_3;
    /// <summary>4.5.4 Valid Basic Self-Issued New With Old Test4</summary>
    procedure Test4_5_4;
    /// <summary>4.5.5 Invalid Basic Self-Issued New With Old Test5</summary>
    procedure Test4_5_5;
    /// <summary>4.5.6 Valid Basic Self-Issued CRL Signing Key Test6</summary>
    procedure Test4_5_6;
    /// <summary>4.5.7 Invalid Basic Self-Issued CRL Signing Key Test7</summary>
    procedure Test4_5_7;
    /// <summary>4.5.8 Invalid Basic Self-Issued CRL Signing Key Test7</summary>
    procedure Test4_5_8;
    /// <summary>4.6.1 Invalid Missing basicConstraints Test1</summary>
    procedure Test4_6_1;
    /// <summary>4.6.2 Invalid cA False Test2</summary>
    procedure Test4_6_2;
    /// <summary>4.6.3 Invalid cA False Test3</summary>
    procedure Test4_6_3;
    /// <summary>4.6.4 Valid basicConstraints Not Critical Test4</summary>
    procedure Test4_6_4;
    /// <summary>4.6.5 Invalid pathLenConstraint Test5</summary>
    procedure Test4_6_5;
    /// <summary>4.6.6 Invalid pathLenConstraint Test6</summary>
    procedure Test4_6_6;
    /// <summary>4.6.7 Valid pathLenConstraint Test7</summary>
    procedure Test4_6_7;
    /// <summary>4.6.8 Valid pathLenConstraint Test8</summary>
    procedure Test4_6_8;
    /// <summary>4.6.9 Invalid pathLenConstraint Test9</summary>
    procedure Test4_6_9;
    /// <summary>4.6.10 Invalid pathLenConstraint Test10</summary>
    procedure Test4_6_10;
    /// <summary>4.6.11 Invalid pathLenConstraint Test11</summary>
    procedure Test4_6_11;
    /// <summary>4.6.12 Invalid pathLenConstraint Test12</summary>
    procedure Test4_6_12;
    /// <summary>4.6.13 Valid pathLenConstraint Test13</summary>
    procedure Test4_6_13;
    /// <summary>4.6.14 Valid pathLenConstraint Test14</summary>
    procedure Test4_6_14;
    /// <summary>4.6.15 Valid Self-Issued pathLenConstraint Test15</summary>
    procedure Test4_6_15;
    /// <summary>4.6.16 Invalid Self-Issued pathLenConstraint Test16</summary>
    procedure Test4_6_16;
    /// <summary>4.6.17 Valid Self-Issued pathLenConstraint Test17</summary>
    procedure Test4_6_17;
    /// <summary>4.7.1 Invalid keyUsage Critical keyCertSign False Test1</summary>
    procedure Test4_7_1;
    /// <summary>4.7.2 Invalid keyUsage Not Critical keyCertSign False Test2</summary>
    procedure Test4_7_2;
    /// <summary>4.7.3 Valid keyUsage Not Critical Test3</summary>
    procedure Test4_7_3;
    /// <summary>4.7.4 Invalid keyUsage Critical cRLSign False Test4</summary>
    procedure Test4_7_4;
    /// <summary>4.7.5 Invalid keyUsage Not Critical cRLSign False Test5</summary>
    procedure Test4_7_5;
    /// <summary>4.8.1 All Certificates Same Policy Test1</summary>
    procedure Test4_8_1;
    /// <summary>4.8.2 All Certificates No Policies Test2</summary>
    procedure Test4_8_2;
    /// <summary>4.8.3 Different Policies Test3</summary>
    procedure Test4_8_3;
    /// <summary>4.8.4 Different Policies Test4</summary>
    procedure Test4_8_4;
    /// <summary>4.8.5 Different Policies Test5</summary>
    procedure Test4_8_5;
    /// <summary>4.8.6 Overlapping Policies Test6</summary>
    procedure Test4_8_6;
    /// <summary>4.8.7 Different Policies Test7</summary>
    procedure Test4_8_7;
    /// <summary>4.8.8 Different Policies Test8</summary>
    procedure Test4_8_8;
    /// <summary>4.8.9 Different Policies Test9</summary>
    procedure Test4_8_9;
    /// <summary>4.8.10 All Certificates Same Policies Test10</summary>
    procedure Test4_8_10;
    /// <summary>4.8.11 All Certificates AnyPolicy Test11</summary>
    procedure Test4_8_11;
    /// <summary>4.8.12 Different Policies Test12</summary>
    procedure Test4_8_12;
    /// <summary>4.8.13 All Certificates Same Policies Test13</summary>
    procedure Test4_8_13;
    /// <summary>4.8.14 AnyPolicy Test14</summary>
    procedure Test4_8_14;
    /// <summary>4.8.15 User Notice Qualifier Test15</summary>
    procedure Test4_8_15;
    /// <summary>4.8.16 User Notice Qualifier Test16</summary>
    procedure Test4_8_16;
    /// <summary>4.8.17 User Notice Qualifier Test17</summary>
    procedure Test4_8_17;
    /// <summary>4.8.18 User Notice Qualifier Test18</summary>
    procedure Test4_8_18;
    /// <summary>4.8.19 User Notice Qualifier Test19</summary>
    procedure Test4_8_19;
    /// <summary>4.8.20 CPS Pointer Qualifier Test20</summary>
    procedure Test4_8_20;
    /// <summary>4.9.1 Valid RequireExplicitPolicy Test1</summary>
    procedure Test4_9_1;
    /// <summary>4.9.2 Valid RequireExplicitPolicy Test2</summary>
    procedure Test4_9_2;
    /// <summary>4.9.3 Invalid RequireExplicitPolicy Test3</summary>
    procedure Test4_9_3;
    /// <summary>4.9.4 Valid RequireExplicitPolicy Test4</summary>
    procedure Test4_9_4;
    /// <summary>4.9.5 Invalid RequireExplicitPolicy Test5</summary>
    procedure Test4_9_5;
    /// <summary>4.9.6 Valid Self-Issued requireExplicitPolicy Test6</summary>
    procedure Test4_9_6;
    /// <summary>4.9.7 Invalid Self-Issued requireExplicitPolicy Test7</summary>
    procedure Test4_9_7;
    /// <summary>4.9.8 Invalid Self-Issued requireExplicitPolicy Test8</summary>
    procedure Test4_9_8;
    /// <summary>4.10.1 Valid Policy Mapping Test1</summary>
    procedure Test4_10_1;
    /// <summary>4.10.2 Invalid Policy Mapping Test2</summary>
    procedure Test4_10_2;
    /// <summary>4.10.3 Valid Policy Mapping Test3</summary>
    procedure Test4_10_3;
    /// <summary>4.10.4 Invalid Policy Mapping Test4</summary>
    procedure Test4_10_4;
    /// <summary>4.10.5 Valid Policy Mapping Test5</summary>
    procedure Test4_10_5;
    /// <summary>4.10.6 Valid Policy Mapping Test6</summary>
    procedure Test4_10_6;
    /// <summary>4.10.7 Invalid Mapping From anyPolicy Test7</summary>
    procedure Test4_10_7;
    /// <summary>4.10.8 Invalid Mapping To anyPolicy Test8</summary>
    procedure Test4_10_8;
    /// <summary>4.10.9 Valid Policy Mapping Test9</summary>
    procedure Test4_10_9;
    /// <summary>4.10.10 Invalid Policy Mapping Test10</summary>
    procedure Test4_10_10;
    /// <summary>4.10.11 Valid Policy Mapping Test11</summary>
    procedure Test4_10_11;
    /// <summary>4.10.12 Valid Policy Mapping Test12</summary>
    procedure Test4_10_12;
    /// <summary>4.10.13 Valid Policy Mapping Test13</summary>
    procedure Test4_10_13;
    /// <summary>4.10.14 Valid Policy Mapping Test14</summary>
    procedure Test4_10_14;
    /// <summary>4.11.1 Invalid inhibitPolicyMapping Test1</summary>
    procedure Test4_11_1;
    /// <summary>4.11.2 Valid inhibitPolicyMapping Test2</summary>
    procedure Test4_11_2;
    /// <summary>4.11.3 Invalid inhibitPolicyMapping Test3</summary>
    procedure Test4_11_3;
    /// <summary>4.11.4 Valid inhibitPolicyMapping Test4</summary>
    procedure Test4_11_4;
    /// <summary>4.11.5 Invalid inhibitPolicyMapping Test5</summary>
    procedure Test4_11_5;
    /// <summary>4.11.6 Invalid inhibitPolicyMapping Test6</summary>
    procedure Test4_11_6;
    /// <summary>4.11.7 Valid Self-Issued inhibitPolicyMapping Test7</summary>
    procedure Test4_11_7;
    /// <summary>4.11.8 Invalid Self-Issued inhibitPolicyMapping Test8</summary>
    procedure Test4_11_8;
    /// <summary>4.11.9 Invalid Self-Issued inhibitPolicyMapping Test9</summary>
    procedure Test4_11_9;
    /// <summary>4.11.10 Invalid Self-Issued inhibitPolicyMapping Test10</summary>
    procedure Test4_11_10;
    /// <summary>4.11.11 Invalid Self-Issued inhibitPolicyMapping Test11</summary>
    procedure Test4_11_11;
    /// <summary>4.12.1 Invalid inhibitAnyPolicy Test1</summary>
    procedure Test4_12_1;
    /// <summary>4.12.2 Valid inhibitAnyPolicy Test2</summary>
    procedure Test4_12_2;
    /// <summary>4.12.3 inhibitAnyPolicy Test3</summary>
    procedure Test4_12_3;
    /// <summary>4.12.4 Invalid inhibitAnyPolicy Test4</summary>
    procedure Test4_12_4;
    /// <summary>4.12.5 Invalid inhibitAnyPolicy Test5</summary>
    procedure Test4_12_5;
    /// <summary>4.12.6 Invalid inhibitAnyPolicy Test6</summary>
    procedure Test4_12_6;
    /// <summary>4.12.7 Valid Self-Issued inhibitAnyPolicy Test7</summary>
    procedure Test4_12_7;
    /// <summary>4.12.8 Invalid Self-Issued inhibitAnyPolicy Test8</summary>
    procedure Test4_12_8;
    /// <summary>4.12.9 Valid Self-Issued inhibitAnyPolicy Test9</summary>
    procedure Test4_12_9;
    /// <summary>4.12.10 Invalid Self-Issued inhibitAnyPolicy Test10</summary>
    procedure Test4_12_10;
    /// <summary>4.13.1 Valid DN nameConstraints Test1</summary>
    procedure Test4_13_1;
    /// <summary>4.13.2 Invalid DN nameConstraints Test2</summary>
    procedure Test4_13_2;
    /// <summary>4.13.3 Invalid DN nameConstraints Test3</summary>
    procedure Test4_13_3;
    /// <summary>4.13.4 Valid DN nameConstraints Test4</summary>
    procedure Test4_13_4;
    /// <summary>4.13.5 Valid DN nameConstraints Test5</summary>
    procedure Test4_13_5;
    /// <summary>4.13.6 Valid DN nameConstraints Test6</summary>
    procedure Test4_13_6;
    /// <summary>4.13.7 Invalid DN nameConstraints Test7</summary>
    procedure Test4_13_7;
    /// <summary>4.13.8 Invalid DN nameConstraints Test8</summary>
    procedure Test4_13_8;
    /// <summary>4.13.9 Invalid DN nameConstraints Test9</summary>
    procedure Test4_13_9;
    /// <summary>4.13.10 Invalid DN nameConstraints Test10</summary>
    procedure Test4_13_10;
    /// <summary>4.13.11 Valid DN nameConstraints Test11</summary>
    procedure Test4_13_11;
    /// <summary>4.13.12 Invalid DN nameConstraints Test12</summary>
    procedure Test4_13_12;
    /// <summary>4.13.13 Invalid DN nameConstraints Test13</summary>
    procedure Test4_13_13;
    /// <summary>4.13.14 Valid DN nameConstraints Test14</summary>
    procedure Test4_13_14;
    /// <summary>4.13.15 Invalid DN nameConstraints Test15</summary>
    procedure Test4_13_15;
    /// <summary>4.13.16 Invalid DN nameConstraints Test16</summary>
    procedure Test4_13_16;
    /// <summary>4.13.17 Invalid DN nameConstraints Test17</summary>
    procedure Test4_13_17;
    /// <summary>4.13.18 Valid DN nameConstraints Test18</summary>
    procedure Test4_13_18;
    /// <summary>4.13.19 Valid Self-Issued DN nameConstraints Test19</summary>
    procedure Test4_13_19;
    /// <summary>4.13.20 Invalid Self-Issued DN nameConstraints Test20</summary>
    procedure Test4_13_20;
    /// <summary>4.13.21 Valid RFC822 nameConstraints Test21</summary>
    procedure Test4_13_21;
    /// <summary>4.13.22 Invalid RFC822 nameConstraints Test22</summary>
    procedure Test4_13_22;
    /// <summary>4.13.23 Valid RFC822 nameConstraints Test23</summary>
    procedure Test4_13_23;
    /// <summary>4.13.24 Invalid RFC822 nameConstraints Test24</summary>
    procedure Test4_13_24;
    /// <summary>4.13.25 Valid RFC822 nameConstraints Test25</summary>
    procedure Test4_13_25;
    /// <summary>4.13.26 Invalid RFC822 nameConstraints Test26</summary>
    procedure Test4_13_26;
    /// <summary>4.13.27 Valid DN and RFC822 nameConstraints Test27</summary>
    procedure Test4_13_27;
    /// <summary>4.13.28 Invalid DN and RFC822 nameConstraints Test28</summary>
    procedure Test4_13_28;
    /// <summary>4.13.29 Invalid DN and RFC822 nameConstraints Test29</summary>
    procedure Test4_13_29;
    /// <summary>4.13.30 Valid DNS nameConstraints Test30</summary>
    procedure Test4_13_30;
    /// <summary>4.13.31 Invalid DNS nameConstraints Test31</summary>
    procedure Test4_13_31;
    /// <summary>4.13.32 Valid DNS nameConstraints Test32</summary>
    procedure Test4_13_32;
    /// <summary>4.13.33 Invalid DNS nameConstraints Test33</summary>
    procedure Test4_13_33;
    /// <summary>4.13.34 Valid URI nameConstraints Test34</summary>
    procedure Test4_13_34;
    /// <summary>4.13.35 Invalid URI nameConstraints Test35</summary>
    procedure Test4_13_35;
    /// <summary>4.13.36 Valid URI nameConstraints Test36</summary>
    procedure Test4_13_36;
    /// <summary>4.13.37 Invalid URI nameConstraints Test37</summary>
    procedure Test4_13_37;
    /// <summary>4.13.38 Invalid DNS nameConstraints Test38</summary>
    procedure Test4_13_38;
    /// <summary>4.14.1 Valid distributionPoint Test1</summary>
    procedure Test4_14_1;
    /// <summary>4.14.2 Invalid distributionPoint Test2</summary>
    procedure Test4_14_2;
    /// <summary>4.14.3 Invalid distributionPoint Test3</summary>
    procedure Test4_14_3;
    /// <summary>4.14.4 Valid distributionPoint Test4</summary>
    procedure Test4_14_4;
    /// <summary>4.14.5 Valid distributionPoint Test5</summary>
    procedure Test4_14_5;
    /// <summary>4.14.6 Invalid distributionPoint Test6</summary>
    procedure Test4_14_6;
    /// <summary>4.14.7 Valid distributionPoint Test7</summary>
    procedure Test4_14_7;
    /// <summary>4.14.8 Invalid distributionPoint Test8</summary>
    procedure Test4_14_8;
    /// <summary>4.14.9 Invalid distributionPoint Test9</summary>
    procedure Test4_14_9;
    /// <summary>4.14.10 Valid No issuingDistributionPoint Test10</summary>
    procedure Test4_14_10;
    /// <summary>4.14.11 Invalid onlyContainsUserCerts CRL Test11</summary>
    procedure Test4_14_11;
    /// <summary>4.14.12 Invalid onlyContainsCACerts CRL Test12</summary>
    procedure Test4_14_12;
    /// <summary>4.14.13 Valid onlyContainsCACerts CRL Test13</summary>
    procedure Test4_14_13;
    /// <summary>4.14.14 Invalid onlyContainsAttributeCerts Test14</summary>
    procedure Test4_14_14;
    /// <summary>4.14.15 Invalid onlySomeReasons Test15</summary>
    procedure Test4_14_15;
    /// <summary>4.14.16 Invalid onlySomeReasons Test16</summary>
    procedure Test4_14_16;
    /// <summary>4.14.17 Invalid onlySomeReasons Test17</summary>
    procedure Test4_14_17;
    /// <summary>4.14.18 Valid onlySomeReasons Test18</summary>
    procedure Test4_14_18;
    /// <summary>4.14.19 Valid onlySomeReasons Test19</summary>
    procedure Test4_14_19;
    /// <summary>4.14.20 Invalid onlySomeReasons Test20</summary>
    procedure Test4_14_20;
    /// <summary>4.14.21 Invalid onlySomeReasons Test21</summary>
    procedure Test4_14_21;
    /// <summary>4.14.22 Valid IDP with indirectCRL Test22</summary>
    procedure Test4_14_22;
    /// <summary>4.14.23 Invalid IDP with indirectCRL Test23</summary>
    procedure Test4_14_23;
    /// <summary>4.14.24 Valid IDP with indirectCRL Test24</summary>
    procedure Test4_14_24;
    /// <summary>4.14.25 Valid IDP with indirectCRL Test25</summary>
    procedure Test4_14_25;
    /// <summary>4.14.26 Invalid IDP with indirectCRL Test26</summary>
    procedure Test4_14_26;
    /// <summary>4.14.27 Invalid cRLIssuer Test27</summary>
    procedure Test4_14_27;
    /// <summary>4.14.28 Valid cRLIssuer Test28</summary>
    procedure Test4_14_28;
    /// <summary>4.14.29 Valid cRLIssuer Test29</summary>
    procedure Test4_14_29;
    /// <summary>4.14.30 Valid cRLIssuer Test30</summary>
    procedure Test4_14_30;
    /// <summary>4.14.31 Invalid cRLIssuer Test31</summary>
    procedure Test4_14_31;
    /// <summary>4.14.32 Invalid cRLIssuer Test32</summary>
    procedure Test4_14_32;
    /// <summary>4.14.33 Valid cRLIssuer Test33</summary>
    procedure Test4_14_33;
    /// <summary>4.14.34 Invalid cRLIssuer Test34</summary>
    procedure Test4_14_34;
    /// <summary>4.14.35 Invalid cRLIssuer Test35</summary>
    procedure Test4_14_35;
    /// <summary>4.15.1 Invalid deltaCRLIndicator No Base Test1</summary>
    procedure Test4_15_1;
    /// <summary>4.15.2 Valid delta-CRL Test2</summary>
    procedure Test4_15_2;
    /// <summary>4.15.3 Invalid delta-CRL Test3</summary>
    procedure Test4_15_3;
    /// <summary>4.15.4 Invalid delta-CRL Test4</summary>
    procedure Test4_15_4;
    /// <summary>4.15.5 Valid delta-CRL Test5</summary>
    procedure Test4_15_5;
    /// <summary>4.15.6 Invalid delta-CRL Test6</summary>
    procedure Test4_15_6;
    /// <summary>4.15.7 Valid delta-CRL Test7</summary>
    procedure Test4_15_7;
    /// <summary>4.15.8 Valid delta-CRL Test8</summary>
    procedure Test4_15_8;
    /// <summary>4.15.9 Invalid delta-CRL Test9</summary>
    procedure Test4_15_9;
    /// <summary>4.15.10 Invalid delta-CRL Test10</summary>
    procedure Test4_15_10;
    /// <summary>4.16.1 Valid Unknown Not Critical Certificate Extension Test1</summary>
    procedure Test4_16_1;
    /// <summary>4.16.2 Invalid Unknown Critical Certificate Extension Test2</summary>
    procedure Test4_16_2;
  end;

implementation

{ TNistCertPathTest }

procedure TNistCertPathTest.Test4_1_1;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Certificate Path Test1 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_1_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid CA Signature Test2 EE')
    .WithCrls(['Bad Signed CA CRL']).WithCerts(['Bad Signed CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_1_3;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid EE Signature Test3 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_1_4;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DSA Signatures Test4 EE')
    .WithCrls(['DSA CA CRL']).WithCerts(['DSA CA Cert']));
end;

procedure TNistCertPathTest.Test4_1_5;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid DSA Parameter Inheritance Test5 EE')
    .WithCrls(['DSA Parameters Inherited CA CRL', 'DSA CA CRL'])
    .WithCerts(['DSA Parameters Inherited CA Cert', 'DSA CA Cert']));
end;

procedure TNistCertPathTest.Test4_1_6;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DSA Signature Test6 EE')
    .WithCrls(['DSA CA CRL']).WithCerts(['DSA CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_2_1;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid CA notBefore Date Test1 EE')
    .WithCrls(['Bad notBefore Date CA CRL'])
    .WithCerts(['Bad notBefore Date CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_2_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid EE notBefore Date Test2 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_2_3;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid pre2000 UTC notBefore Date Test3 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_2_4;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid GeneralizedTime notBefore Date Test4 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_2_5;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid CA notAfter Date Test5 EE')
    .WithCrls(['Bad notAfter Date CA CRL'])
    .WithCerts(['Bad notAfter Date CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_2_6;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid EE notAfter Date Test6 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_2_7;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid pre2000 UTC EE notAfter Date Test7 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_2_8;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid GeneralizedTime notAfter Date Test8 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_1;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Name Chaining Test1 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_3_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Name Chaining Order Test2 EE')
    .WithCrls(['Name Order CA CRL']).WithCerts(['Name Ordering CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_3_3;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Name Chaining Whitespace Test3 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_4;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Name Chaining Whitespace Test4 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_5;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Name Chaining Capitalization Test5 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_6;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Name UIDs Test6 EE')
    .WithCrls(['UID CA CRL']).WithCerts(['UID CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_7;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid RFC3280 Mandatory Attribute Types Test7 EE')
    .WithCrls(['RFC3280 Mandatory AttributeTypes CA CRL'])
    .WithCerts(['RFC3280 Mandatory Attribute Types CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_8;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid RFC3280 Optional Attribute Types Test8 EE')
    .WithCrls(['RFC3280 Optional AttributeTypes CA CRL'])
    .WithCerts(['RFC3280 Optional Attribute Types CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_9;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid UTF8String Encoded Names Test9 EE')
    .WithCrls(['UTF8String Encoded Names CA CRL'])
    .WithCerts(['UTF8String Encoded Names CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_10;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Rollover from PrintableString to UTF8String Test10 EE')
    .WithCrls(['Rollover fromPrintableString to UTF8String CA CRL'])
    .WithCerts(['Rollover from PrintableString to UTF8String CA Cert']));
end;

procedure TNistCertPathTest.Test4_3_11;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid UTF8String Case Insensitive Match Test11 EE')
    .WithCrls(['UTF8String Case InsensitiveMatch CA CRL'])
    .WithCerts(['UTF8String Case Insensitive Match CA Cert']));
end;

procedure TNistCertPathTest.Test4_4_1;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Missing CRL Test1 EE')
    .WithCerts(['No CRL CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Revoked CA Test2 EE')
    .WithCrls(['Revoked subCA CRL', 'Good CA CRL'])
    .WithCerts(['Revoked subCA Cert', 'Good CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_4_3;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Revoked EE Test3 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_4;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Bad CRL Signature Test4 EE')
    .WithCrls(['Bad CRL Signature CA CRL'])
    .WithCerts(['Bad CRL Signature CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_5;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Bad CRL Issuer Name Test5 EE')
    .WithCrls(['Bad CRL Issuer Name CA CRL'])
    .WithCerts(['Bad CRL Issuer Name CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_6;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Wrong CRL Test6 EE')
    .WithCrls(['Wrong CRL CA CRL']).WithCerts(['Wrong CRL CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_7;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Two CRLs Test7 EE')
    .WithCrls(['Two CRLs CA Bad CRL', 'Two CRLs CA Good CRL'])
    .WithCerts(['Two CRLs CA Cert']));
end;

procedure TNistCertPathTest.Test4_4_8;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Unknown CRL Entry Extension Test8 EE')
    .WithCrls(['Unknown CRL Entry Extension CACRL'])
    .WithCerts(['Unknown CRL Entry Extension CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_9;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Unknown CRL Extension Test9 EE')
    .WithCrls(['Unknown CRL Extension CA CRL'])
    .WithCerts(['Unknown CRL Extension CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_10;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Unknown CRL Extension Test10 EE')
    .WithCrls(['Unknown CRL Extension CA CRL'])
    .WithCerts(['Unknown CRL Extension CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_11;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Old CRL nextUpdate Test11 EE')
    .WithCrls(['Old CRL nextUpdate CA CRL'])
    .WithCerts(['Old CRL nextUpdate CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_12;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid pre2000 CRL nextUpdate Test12 EE')
    .WithCrls(['pre2000 CRL nextUpdate CA CRL'])
    .WithCerts(['pre2000 CRL nextUpdate CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_13;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid GeneralizedTime CRL nextUpdate Test13 EE')
    .WithCrls(['GeneralizedTime CRL nextUpdateCA CRL'])
    .WithCerts(['GeneralizedTime CRL nextUpdate CA Cert']));
end;

procedure TNistCertPathTest.Test4_4_14;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Negative Serial Number Test14 EE')
    .WithCrls(['Negative Serial Number CA CRL'])
    .WithCerts(['Negative Serial Number CA Cert']));
end;

procedure TNistCertPathTest.Test4_4_15;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Negative Serial Number Test15 EE')
    .WithCrls(['Negative Serial Number CA CRL'])
    .WithCerts(['Negative Serial Number CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_16;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Long Serial Number Test16 EE')
    .WithCrls(['Long Serial Number CA CRL'])
    .WithCerts(['Long Serial Number CA Cert']));
end;

procedure TNistCertPathTest.Test4_4_17;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Long Serial Number Test17 EE')
    .WithCrls(['Long Serial Number CA CRL'])
    .WithCerts(['Long Serial Number CA Cert']));
end;

procedure TNistCertPathTest.Test4_4_18;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Long Serial Number Test18 EE')
    .WithCrls(['Long Serial Number CA CRL'])
    .WithCerts(['Long Serial Number CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_19;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Separate Certificate and CRL Keys Test19 EE')
    .WithCrls(['Separate Certificate and CRLKeys CRL'])
    .WithCerts(['Separate Certificate and CRL Keys Certificate Signing CA Cert'])
    .WithCrlSignerCerts(['SeparateCertificate and CRL Keys CRL Signing Cert']));
end;

procedure TNistCertPathTest.Test4_4_20;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Separate Certificate and CRL Keys Test20 EE')
    .WithCrls(['Separate Certificate and CRLKeys CRL'])
    .WithCerts(['Separate Certificate and CRL Keys Certificate Signing CA Cert'])
    .WithCrlSignerCerts(['SeparateCertificate and CRL Keys CRL Signing Cert']), 0);
end;

procedure TNistCertPathTest.Test4_4_21;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Separate Certificate and CRL Keys Test21 EE')
    .WithCrls(['Separate Certificate and CRLKeys CA2 CRL'])
    .WithCerts(['Separate Certificate and CRL Keys CA2 Certificate Signing CA Cert'])
    .WithCrlSignerCerts(['SeparateCertificate and CRL Keys CA2 CRL Signing Cert']), 0);
end;

procedure TNistCertPathTest.Test4_5_1;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Basic SelfIssued Old With New Test1 EE')
    .WithCerts(['Basic SelfIssued New Key OldWithNew CA Cert', 'Basic SelfIssued New Key CA Cert'])
    .WithCrls(['Basic SelfIssued New Key CA CRL']));
end;

procedure TNistCertPathTest.Test4_5_2;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Basic SelfIssued Old With New Test2 EE')
    .WithCerts(['Basic SelfIssued New Key OldWithNew CA Cert', 'Basic SelfIssued New Key CA Cert'])
    .WithCrls(['Basic SelfIssued New Key CA CRL']), 0);
end;

procedure TNistCertPathTest.Test4_5_3;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Basic SelfIssued New With Old Test3 EE')
    .WithCrls(['Basic SelfIssued Old Key CACRL', 'Basic SelfIssued Old Key SelfIssued CertCRL'])
    .WithCerts(['Basic SelfIssued Old Key NewWithOld CA Cert', 'Basic SelfIssued Old Key CA Cert']));
end;

procedure TNistCertPathTest.Test4_5_4;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Basic SelfIssued New With Old Test4 EE')
    .WithCrls(['Basic SelfIssued Old Key CACRL', 'Basic SelfIssued Old Key SelfIssued CertCRL'])
    .WithCerts(['Basic SelfIssued Old Key CA Cert'])
    .WithCrlSignerCerts(['Basic SelfIssued Old Key NewWithOld CA Cert']));
end;

procedure TNistCertPathTest.Test4_5_5;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Basic SelfIssued New With Old Test5 EE')
    .WithCrls(['Basic SelfIssued Old Key CACRL', 'Basic SelfIssued Old Key SelfIssued CertCRL'])
    .WithCerts(['Basic SelfIssued Old Key CA Cert'])
    .WithCrlSignerCerts(['Basic SelfIssued Old Key NewWithOld CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_5_6;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Basic SelfIssued CRL Signing Key Test6 EE')
    .WithCrls(['Basic SelfIssued CRL SigningKey CA CRL'])
    .WithCrlSignerCerts(['Basic SelfIssued CRL Signing Key CRL Cert'])
    .WithCrls(['Basic SelfIssued CRL SigningKey CRL Cert CRL'])
    .WithCerts(['Basic SelfIssued CRL Signing Key CA Cert']));
end;

procedure TNistCertPathTest.Test4_5_7;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Basic SelfIssued CRL Signing Key Test7 EE')
    .WithCrls(['Basic SelfIssued CRL SigningKey CA CRL', 'Basic SelfIssued CRL SigningKey CRL Cert CRL'])
    .WithCerts(['Basic SelfIssued CRL Signing Key CRL Cert', 'Basic SelfIssued CRL Signing Key CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_5_8;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Basic SelfIssued CRL Signing Key Test8 EE')
    .WithCrls(['Basic SelfIssued CRL SigningKey CA CRL'])
    .WithCerts(['Basic SelfIssued CRL Signing Key CRL Cert'])
    .WithCrls(['Basic SelfIssued CRL SigningKey CRL Cert CRL'])
    .WithCerts(['Basic SelfIssued CRL Signing Key CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_1;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Missing basicConstraints Test1 EE')
    .WithCrls(['Missing basicConstraints CA CRL'])
    .WithCerts(['Missing basicConstraints CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid cA False Test2 EE')
    .WithCrls(['basicConstraints Critical cA FalseCA CRL'])
    .WithCerts(['basicConstraints Critical cA False CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_3;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid cA False Test3 EE')
    .WithCrls(['basicConstraints Not CriticalcA False CA CRL'])
    .WithCerts(['basicConstraints Not Critical cA False CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_4;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid basicConstraints Not Critical Test4 EE')
    .WithCrls(['basicConstraints Not Critical CA CRL'])
    .WithCerts(['basicConstraints Not Critical CA Cert']));
end;

procedure TNistCertPathTest.Test4_6_5;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid pathLenConstraint Test5 EE')
    .WithCrls(['pathLenConstraint0 subCA CRL', 'pathLenConstraint0 CA CRL'])
    .WithCerts(['pathLenConstraint0 subCA Cert', 'pathLenConstraint0 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_6;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid pathLenConstraint Test6 EE')
    .WithCrls(['pathLenConstraint0 subCA CRL', 'pathLenConstraint0 CA CRL'])
    .WithCerts(['pathLenConstraint0 subCA Cert', 'pathLenConstraint0 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_7;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid pathLenConstraint Test7 EE')
    .WithCrls(['pathLenConstraint0 CA CRL'])
    .WithCerts(['pathLenConstraint0 CA Cert']));
end;

procedure TNistCertPathTest.Test4_6_8;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid pathLenConstraint Test8 EE')
    .WithCrls(['pathLenConstraint0 CA CRL'])
    .WithCerts(['pathLenConstraint0 CA Cert']));
end;

procedure TNistCertPathTest.Test4_6_9;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid pathLenConstraint Test9 EE')
    .WithCrls(['pathLenConstraint6 subsubCA00 CRL', 'pathLenConstraint6 subCA0 CRL', 'pathLenConstraint6 CA CRL'])
    .WithCerts(['pathLenConstraint6 subsubCA00 Cert', 'pathLenConstraint6 subCA0 Cert', 'pathLenConstraint6 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_10;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid pathLenConstraint Test10 EE')
    .WithCrls(['pathLenConstraint6 subsubCA00 CRL', 'pathLenConstraint6 subCA0 CRL', 'pathLenConstraint6 CA CRL'])
    .WithCerts(['pathLenConstraint6 subsubCA00 Cert', 'pathLenConstraint6 subCA0 Cert', 'pathLenConstraint6 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_11;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid pathLenConstraint Test11 EE')
    .WithCrls(['pathLenConstraint6subsubsubCA11X CRL', 'pathLenConstraint6 subsubCA11 CRL', 'pathLenConstraint6 subCA1 CRL', 'pathLenConstraint6 CA CRL'])
    .WithCerts(['pathLenConstraint6 subsubsubCA11X Cert', 'pathLenConstraint6 subsubCA11 Cert', 'pathLenConstraint6 subCA1 Cert', 'pathLenConstraint6 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_12;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid pathLenConstraint Test12 EE')
    .WithCrls(['pathLenConstraint6subsubsubCA11X CRL', 'pathLenConstraint6 subsubCA11 CRL', 'pathLenConstraint6 subCA1 CRL', 'pathLenConstraint6 CA CRL'])
    .WithCerts(['pathLenConstraint6 subsubsubCA11X Cert', 'pathLenConstraint6 subsubCA11 Cert', 'pathLenConstraint6 subCA1 Cert', 'pathLenConstraint6 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_13;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid pathLenConstraint Test13 EE')
    .WithCrls(['pathLenConstraint6subsubsubCA41X CRL', 'pathLenConstraint6 subsubCA41 CRL', 'pathLenConstraint6 subCA4 CRL', 'pathLenConstraint6 CA CRL'])
    .WithCerts(['pathLenConstraint6 subsubsubCA41X Cert', 'pathLenConstraint6 subsubCA41 Cert', 'pathLenConstraint6 subCA4 Cert', 'pathLenConstraint6 CA Cert']));
end;

procedure TNistCertPathTest.Test4_6_14;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid pathLenConstraint Test14 EE')
    .WithCrls(['pathLenConstraint6subsubsubCA41X CRL', 'pathLenConstraint6 subsubCA41 CRL', 'pathLenConstraint6 subCA4 CRL', 'pathLenConstraint6 CA CRL'])
    .WithCerts(['pathLenConstraint6 subsubsubCA41X Cert', 'pathLenConstraint6 subsubCA41 Cert', 'pathLenConstraint6 subCA4 Cert', 'pathLenConstraint6 CA Cert']));
end;

procedure TNistCertPathTest.Test4_6_15;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid SelfIssued pathLenConstraint Test15 EE')
    .WithCerts(['pathLenConstraint0 SelfIssued CA Cert', 'pathLenConstraint0 CA Cert'])
    .WithCrls(['pathLenConstraint0 CA CRL']));
end;

procedure TNistCertPathTest.Test4_6_16;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued pathLenConstraint Test16 EE')
    .WithCrls(['pathLenConstraint0 subCA2 CRL', 'pathLenConstraint0 CA CRL'])
    .WithCerts(['pathLenConstraint0 subCA2 Cert', 'pathLenConstraint0 SelfIssued CA Cert', 'pathLenConstraint0 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_6_17;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid SelfIssued pathLenConstraint Test17 EE')
    .WithCerts(['pathLenConstraint1 SelfIssued subCA Cert', 'pathLenConstraint1 subCA Cert', 'pathLenConstraint1 SelfIssued CA Cert', 'pathLenConstraint1 CA Cert'])
    .WithCrls(['pathLenConstraint1 subCA CRL', 'pathLenConstraint1 CA CRL']));
end;

procedure TNistCertPathTest.Test4_7_1;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid keyUsage Critical keyCertSign False Test1 EE')
    .WithCrls(['keyUsage Critical keyCertSignFalse CA CRL'])
    .WithCerts(['keyUsage Critical keyCertSign False CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_7_2;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid keyUsage Not Critical keyCertSign False Test2 EE')
    .WithCrls(['keyUsage Not CriticalkeyCertSign False CA CRL'])
    .WithCerts(['keyUsage Not Critical keyCertSign False CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_7_3;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid keyUsage Not Critical Test3 EE')
    .WithCrls(['keyUsage Not Critical CA CRL'])
    .WithCerts(['keyUsage Not Critical CA Cert']));
end;

procedure TNistCertPathTest.Test4_7_4;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid keyUsage Critical cRLSign False Test4 EE')
    .WithCrls(['keyUsage Critical cRLSign False CACRL'])
    .WithCerts(['keyUsage Critical cRLSign False CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_7_5;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid keyUsage Not Critical cRLSign False Test5 EE')
    .WithCrls(['keyUsage Not Critical cRLSignFalse CA CRL'])
    .WithCerts(['keyUsage Not Critical cRLSign False CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_8_1;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Certificate Path Test1 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert'])
    .WithExplicitPolicyRequired(True));
  CheckAccepted(NewTest().WithEndEntity('Valid Certificate Path Test1 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert'])
    .WithExplicitPolicyRequired(True)
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckRejected(NewTest().WithEndEntity('Valid Certificate Path Test1 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert'])
    .WithExplicitPolicyRequired(True)
    .WithPoliciesByName(['NIST-test-policy-2']), -1);
  CheckAccepted(NewTest().WithEndEntity('Valid Certificate Path Test1 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert'])
    .WithExplicitPolicyRequired(True)
    .WithPoliciesByName(['NIST-test-policy-1', 'NIST-test-policy-2']));
end;

procedure TNistCertPathTest.Test4_8_2;
begin
  CheckAccepted(NewTest().WithEndEntity('All Certificates No Policies Test2 EE')
    .WithCrls(['No Policies CA CRL']).WithCerts(['No Policies CA Cert']));
  CheckRejected(NewTest().WithEndEntity('All Certificates No Policies Test2 EE')
    .WithCrls(['No Policies CA CRL']).WithCerts(['No Policies CA Cert'])
    .WithExplicitPolicyRequired(True), 1);
end;

procedure TNistCertPathTest.Test4_8_3;
begin
  CheckAccepted(NewTest().WithEndEntity('Different Policies Test3 EE')
    .WithCrls(['Policies P2 subCA CRL', 'Good CA CRL'])
    .WithCerts(['Policies P2 subCA Cert', 'Good CA Cert']));
  CheckRejected(NewTest().WithEndEntity('Different Policies Test3 EE')
    .WithCrls(['Policies P2 subCA CRL', 'Good CA CRL'])
    .WithCerts(['Policies P2 subCA Cert', 'Good CA Cert'])
    .WithExplicitPolicyRequired(True), 1);
  CheckRejected(NewTest().WithEndEntity('Different Policies Test3 EE')
    .WithCrls(['Policies P2 subCA CRL', 'Good CA CRL'])
    .WithCerts(['Policies P2 subCA Cert', 'Good CA Cert'])
    .WithExplicitPolicyRequired(True)
    .WithPoliciesByName(['NIST-test-policy-1', 'NIST-test-policy-2']), 1);
end;

procedure TNistCertPathTest.Test4_8_4;
begin
  CheckRejected(NewTest().WithEndEntity('Different Policies Test4 EE')
    .WithCrls(['Good subCA CRL', 'Good CA CRL'])
    .WithCerts(['Good subCA Cert', 'Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_8_5;
begin
  CheckRejected(NewTest().WithEndEntity('Different Policies Test5 EE')
    .WithCrls(['Policies P2 subCA2 CRL', 'Good CA CRL'])
    .WithCerts(['Policies P2 subCA2 Cert', 'Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_8_6;
begin
  CheckAccepted(NewTest().WithEndEntity('Overlapping Policies Test6 EE')
    .WithCrls(['Policies P1234 subsubCAP123P12CRL', 'Policies P1234 subCAP123 CRL', 'Policies P1234 CA CRL'])
    .WithCerts(['Policies P1234 subsubCAP123P12 Cert', 'Policies P1234 subCAP123 Cert', 'Policies P1234 CA Cert']));
  CheckAccepted(NewTest().WithEndEntity('Overlapping Policies Test6 EE')
    .WithCrls(['Policies P1234 subsubCAP123P12CRL', 'Policies P1234 subCAP123 CRL', 'Policies P1234 CA CRL'])
    .WithCerts(['Policies P1234 subsubCAP123P12 Cert', 'Policies P1234 subCAP123 Cert', 'Policies P1234 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckRejected(NewTest().WithEndEntity('Overlapping Policies Test6 EE')
    .WithCrls(['Policies P1234 subsubCAP123P12CRL', 'Policies P1234 subCAP123 CRL', 'Policies P1234 CA CRL'])
    .WithCerts(['Policies P1234 subsubCAP123P12 Cert', 'Policies P1234 subCAP123 Cert', 'Policies P1234 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']), -1);
end;

procedure TNistCertPathTest.Test4_8_7;
begin
  CheckRejected(NewTest().WithEndEntity('Different Policies Test7 EE')
    .WithCrls(['Policies P123 subsubCAP12P1 CRL', 'Policies P123 subCAP12 CRL', 'Policies P123 CA CRL'])
    .WithCerts(['Policies P123 subsubCAP12P1 Cert', 'Policies P123 subCAP12 Cert', 'Policies P123 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_8_8;
begin
  CheckRejected(NewTest().WithEndEntity('Different Policies Test8 EE')
    .WithCrls(['Policies P12 subsubCAP1P2 CRL', 'Policies P12 subCAP1 CRL', 'Policies P12 CA CRL'])
    .WithCerts(['Policies P12 subsubCAP1P2 Cert', 'Policies P12 subCAP1 Cert', 'Policies P12 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_8_9;
begin
  CheckRejected(NewTest().WithEndEntity('Different Policies Test9 EE')
    .WithCrls(['Policies P123subsubsubCAP12P2P1 CRL', 'Policies P123 subsubCAP2P2 CRL', 'Policies P123 subCAP12 CRL', 'Policies P123 CA CRL'])
    .WithCerts(['Policies P123 subsubsubCAP12P2P1 Cert', 'Policies P123 subsubCAP12P2 Cert', 'Policies P123 subCAP12 Cert', 'Policies P123 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_8_10;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('All Certificates Same Policies Test10 EE')
    .WithCrls(['Policies P12 CA CRL']).WithCerts(['Policies P12 CA Cert']));
  CheckAccepted(NewTest()
    .WithEndEntity('All Certificates Same Policies Test10 EE')
    .WithCrls(['Policies P12 CA CRL']).WithCerts(['Policies P12 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckAccepted(NewTest()
    .WithEndEntity('All Certificates Same Policies Test10 EE')
    .WithCrls(['Policies P12 CA CRL']).WithCerts(['Policies P12 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']));
end;

procedure TNistCertPathTest.Test4_8_11;
begin
  CheckAccepted(NewTest().WithEndEntity('All Certificates anyPolicy Test11 EE')
    .WithCrls(['anyPolicy CA CRL']).WithCerts(['anyPolicy CA Cert']));
  CheckAccepted(NewTest().WithEndEntity('All Certificates anyPolicy Test11 EE')
    .WithCrls(['anyPolicy CA CRL']).WithCerts(['anyPolicy CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
end;

procedure TNistCertPathTest.Test4_8_12;
begin
  CheckRejected(NewTest().WithEndEntity('Different Policies Test12 EE')
    .WithCrls(['Policies P3 CA CRL']).WithCerts(['Policies P3 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_8_13;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('All Certificates Same Policies Test13 EE')
    .WithCrls(['Policies P123 CA CRL']).WithCerts(['Policies P123 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckAccepted(NewTest()
    .WithEndEntity('All Certificates Same Policies Test13 EE')
    .WithCrls(['Policies P123 CA CRL']).WithCerts(['Policies P123 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']));
  CheckAccepted(NewTest()
    .WithEndEntity('All Certificates Same Policies Test13 EE')
    .WithCrls(['Policies P123 CA CRL']).WithCerts(['Policies P123 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-3']));
end;

procedure TNistCertPathTest.Test4_8_14;
begin
  CheckAccepted(NewTest().WithEndEntity('AnyPolicy Test14 EE')
    .WithCrls(['anyPolicy CA CRL']).WithCerts(['anyPolicy CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckRejected(NewTest().WithEndEntity('AnyPolicy Test14 EE')
    .WithCrls(['anyPolicy CA CRL']).WithCerts(['anyPolicy CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']), -1);
end;

procedure TNistCertPathTest.Test4_8_15;
begin
  CheckAccepted(NewTest().WithEndEntity('User Notice Qualifier Test15 EE'));
  CheckRejected(NewTest().WithPoliciesByName(['NIST-test-policy-2'])
    .WithEndEntity('User Notice Qualifier Test15 EE'), -1);
end;

procedure TNistCertPathTest.Test4_8_16;
begin
  CheckAccepted(NewTest().WithEndEntity('User Notice Qualifier Test16 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
end;

procedure TNistCertPathTest.Test4_8_17;
begin
  CheckAccepted(NewTest().WithEndEntity('User Notice Qualifier Test17 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
end;

procedure TNistCertPathTest.Test4_8_18;
begin
  CheckAccepted(NewTest().WithEndEntity('User Notice Qualifier Test18 EE')
    .WithCrls(['Policies P12 CA CRL']).WithCerts(['Policies P12 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckAccepted(NewTest().WithEndEntity('User Notice Qualifier Test18 EE')
    .WithCrls(['Policies P12 CA CRL']).WithCerts(['Policies P12 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']));
end;

procedure TNistCertPathTest.Test4_8_19;
begin
  CheckAccepted(NewTest().WithEndEntity('User Notice Qualifier Test19 EE'));
end;

procedure TNistCertPathTest.Test4_8_20;
begin
  CheckAccepted(NewTest().WithEndEntity('CPS Pointer Qualifier Test20 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_9_1;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid requireExplicitPolicy Test1 EE')
    .WithCrls(['requireExplicitPolicy10subsubsubCA CRL', 'requireExplicitPolicy10 subsubCACRL', 'requireExplicitPolicy10 subCA CRL', 'requireExplicitPolicy10 CA CRL'])
    .WithCerts(['requireExplicitPolicy10 subsubsubCA Cert', 'requireExplicitPolicy10 subsubCA Cert', 'requireExplicitPolicy10 subCA Cert', 'requireExplicitPolicy10 CA Cert']));
end;

procedure TNistCertPathTest.Test4_9_2;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid requireExplicitPolicy Test2 EE')
    .WithCrls(['requireExplicitPolicy5 subsubsubCACRL', 'requireExplicitPolicy5 subsubCA CRL', 'requireExplicitPolicy5 subCA CRL', 'requireExplicitPolicy5 CA CRL'])
    .WithCerts(['requireExplicitPolicy5 subsubsubCA Cert', 'requireExplicitPolicy5 subsubCA Cert', 'requireExplicitPolicy5 subCA Cert', 'requireExplicitPolicy5 CA Cert']));
end;

procedure TNistCertPathTest.Test4_9_3;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid requireExplicitPolicy Test3 EE')
    .WithCrls(['requireExplicitPolicy4 subsubsubCACRL', 'requireExplicitPolicy4 subsubCA CRL', 'requireExplicitPolicy4 subCA CRL', 'requireExplicitPolicy4 CA CRL'])
    .WithCerts(['requireExplicitPolicy4 subsubsubCA Cert', 'requireExplicitPolicy4 subsubCA Cert', 'requireExplicitPolicy4 subCA Cert', 'requireExplicitPolicy4 CA Cert']), -1);
end;

procedure TNistCertPathTest.Test4_9_4;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid requireExplicitPolicy Test4 EE')
    .WithCrls(['requireExplicitPolicy0 subsubsubCACRL', 'requireExplicitPolicy0 subsubCA CRL', 'requireExplicitPolicy0 subCA CRL', 'requireExplicitPolicy0 CA CRL'])
    .WithCerts(['requireExplicitPolicy0 subsubsubCA Cert', 'requireExplicitPolicy0 subsubCA Cert', 'requireExplicitPolicy0 subCA Cert', 'requireExplicitPolicy0 CA Cert']));
end;

procedure TNistCertPathTest.Test4_9_5;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid requireExplicitPolicy Test5 EE')
    .WithCrls(['requireExplicitPolicy7subsubsubCARE2RE4 CRL', 'requireExplicitPolicy7subsubCARE2RE4 CRL', 'requireExplicitPolicy7 subCARE2 CRL', 'requireExplicitPolicy7 CA CRL'])
    .WithCerts(['requireExplicitPolicy7 subsubsubCARE2RE4 Cert', 'requireExplicitPolicy7 subsubCARE2RE4 Cert', 'requireExplicitPolicy7 subCARE2 Cert', 'requireExplicitPolicy7 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_9_6;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid SelfIssued requireExplicitPolicy Test6 EE')
    .WithCerts(['requireExplicitPolicy2 SelfIssued CA Cert', 'requireExplicitPolicy2 CA Cert'])
    .WithCrls(['requireExplicitPolicy2 CA CRL']));
end;

procedure TNistCertPathTest.Test4_9_7;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued requireExplicitPolicy Test7 EE')
    .WithCrls(['requireExplicitPolicy2 subCA CRL', 'requireExplicitPolicy2 CA CRL'])
    .WithCerts(['requireExplicitPolicy2 subCA Cert', 'requireExplicitPolicy2 SelfIssued CA Cert', 'requireExplicitPolicy2 CA Cert']), -1);
end;

procedure TNistCertPathTest.Test4_9_8;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued requireExplicitPolicy Test8 EE')
    .WithCerts(['requireExplicitPolicy2 SelfIssued subCA Cert', 'requireExplicitPolicy2 subCA Cert', 'requireExplicitPolicy2 SelfIssued CA Cert', 'requireExplicitPolicy2 CA Cert'])
    .WithCrls(['requireExplicitPolicy2 subCA CRL', 'requireExplicitPolicy2 CA CRL']), -1);
end;

procedure TNistCertPathTest.Test4_10_1;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test1 EE')
    .WithCrls(['Mapping 1to2 CA CRL']).WithCerts(['Mapping 1to2 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckRejected(NewTest().WithEndEntity('Valid Policy Mapping Test1 EE')
    .WithCrls(['Mapping 1to2 CA CRL']).WithCerts(['Mapping 1to2 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']), -1);
  CheckRejected(NewTest().WithEndEntity('Valid Policy Mapping Test1 EE')
    .WithCrls(['Mapping 1to2 CA CRL']).WithCerts(['Mapping 1to2 CA Cert'])
    .WithPolicyMappingInhibited(True), 0);
end;

procedure TNistCertPathTest.Test4_10_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Policy Mapping Test2 EE')
    .WithCrls(['Mapping 1to2 CA CRL']).WithCerts(['Mapping 1to2 CA Cert']), 0);
  CheckRejected(NewTest().WithEndEntity('Invalid Policy Mapping Test2 EE')
    .WithCrls(['Mapping 1to2 CA CRL']).WithCerts(['Mapping 1to2 CA Cert'])
    .WithPolicyMappingInhibited(True), 0);
end;

procedure TNistCertPathTest.Test4_10_3;
begin
  CheckRejected(NewTest().WithEndEntity('Valid Policy Mapping Test3 EE')
    .WithCrls(['P12 Mapping 1to3 subsubCA CRL', 'P12 Mapping 1to3 subCA CRL', 'P12 Mapping 1to3 CA CRL'])
    .WithCerts(['P12 Mapping 1to3 subsubCA Cert', 'P12 Mapping 1to3 subCA Cert', 'P12 Mapping 1to3 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']), -1);
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test3 EE')
    .WithCrls(['P12 Mapping 1to3 subsubCA CRL', 'P12 Mapping 1to3 subCA CRL', 'P12 Mapping 1to3 CA CRL'])
    .WithCerts(['P12 Mapping 1to3 subsubCA Cert', 'P12 Mapping 1to3 subCA Cert', 'P12 Mapping 1to3 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']));
end;

procedure TNistCertPathTest.Test4_10_4;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Policy Mapping Test4 EE')
    .WithCrls(['P12 Mapping 1to3 subsubCA CRL', 'P12 Mapping 1to3 subCA CRL', 'P12 Mapping 1to3 CA CRL'])
    .WithCerts(['P12 Mapping 1to3 subsubCA Cert', 'P12 Mapping 1to3 subCA Cert', 'P12 Mapping 1to3 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_10_5;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test5 EE')
    .WithCrls(['P1 Mapping 1to234 subCA CRL', 'P1 Mapping 1to234 CA CRL'])
    .WithCerts(['P1 Mapping 1to234 subCA Cert', 'P1 Mapping 1to234 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckRejected(NewTest().WithEndEntity('Valid Policy Mapping Test5 EE')
    .WithCrls(['P1 Mapping 1to234 subCA CRL', 'P1 Mapping 1to234 CA CRL'])
    .WithCerts(['P1 Mapping 1to234 subCA Cert', 'P1 Mapping 1to234 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-6']), -1);
end;

procedure TNistCertPathTest.Test4_10_6;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test6 EE')
    .WithCrls(['P1 Mapping 1to234 subCA CRL', 'P1 Mapping 1to234 CA CRL'])
    .WithCerts(['P1 Mapping 1to234 subCA Cert', 'P1 Mapping 1to234 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckRejected(NewTest().WithEndEntity('Valid Policy Mapping Test6 EE')
    .WithCrls(['P1 Mapping 1to234 subCA CRL', 'P1 Mapping 1to234 CA CRL'])
    .WithCerts(['P1 Mapping 1to234 subCA Cert', 'P1 Mapping 1to234 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-6']), -1);
end;

procedure TNistCertPathTest.Test4_10_7;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Mapping From anyPolicy Test7 EE')
    .WithCrls(['Mapping From anyPolicy CA CRL'])
    .WithCerts(['Mapping From anyPolicy CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_10_8;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Mapping To anyPolicy Test8 EE')
    .WithCrls(['Mapping To anyPolicy CA CRL'])
    .WithCerts(['Mapping To anyPolicy CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_10_9;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test9 EE')
    .WithCrls(['PanyPolicy Mapping 1to2 CA CRL'])
    .WithCerts(['PanyPolicy Mapping 1to2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_10_10;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid Policy Mapping Test10 EE')
    .WithCrls(['Good subCA PanyPolicyMapping 1to2 CA CRL', 'Good CA CRL'])
    .WithCerts(['Good subCA PanyPolicy Mapping 1to2 CA Cert', 'Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_10_11;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test11 EE')
    .WithCrls(['Good subCA PanyPolicyMapping 1to2 CA CRL', 'Good CA CRL'])
    .WithCerts(['Good subCA PanyPolicy Mapping 1to2 CA Cert', 'Good CA Cert']));
end;

procedure TNistCertPathTest.Test4_10_12;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test12 EE')
    .WithCrls(['P12 Mapping 1to3 CA CRL'])
    .WithCerts(['P12 Mapping 1to3 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-1']));
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test12 EE')
    .WithCrls(['P12 Mapping 1to3 CA CRL'])
    .WithCerts(['P12 Mapping 1to3 CA Cert'])
    .WithPoliciesByName(['NIST-test-policy-2']));
end;

procedure TNistCertPathTest.Test4_10_13;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test13 EE')
    .WithCrls(['P1anyPolicy Mapping 1to2 CA CRL'])
    .WithCerts(['P1anyPolicy Mapping 1to2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_10_14;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid Policy Mapping Test14 EE')
    .WithCrls(['P1anyPolicy Mapping 1to2 CA CRL'])
    .WithCerts(['P1anyPolicy Mapping 1to2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_11_1;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitPolicyMapping Test1 EE')
    .WithCrls(['inhibitPolicyMapping0 subCA CRL', 'inhibitPolicyMapping0 CA CRL'])
    .WithCerts(['inhibitPolicyMapping0 subCA Cert', 'inhibitPolicyMapping0 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_11_2;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid inhibitPolicyMapping Test2 EE')
    .WithCrls(['inhibitPolicyMapping1 P12 subCACRL', 'inhibitPolicyMapping1 P12 CA CRL'])
    .WithCerts(['inhibitPolicyMapping1 P12 subCA Cert', 'inhibitPolicyMapping1 P12 CA Cert']));
end;

procedure TNistCertPathTest.Test4_11_3;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitPolicyMapping Test3 EE')
    .WithCrls(['inhibitPolicyMapping1 P12subsubCA CRL', 'inhibitPolicyMapping1 P12 subCACRL', 'inhibitPolicyMapping1 P12 CA CRL'])
    .WithCerts(['inhibitPolicyMapping1 P12 subsubCA Cert', 'inhibitPolicyMapping1 P12 subCA Cert', 'inhibitPolicyMapping1 P12 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_11_4;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid inhibitPolicyMapping Test4 EE')
    .WithCrls(['inhibitPolicyMapping1 P12subsubCA CRL', 'inhibitPolicyMapping1 P12 subCACRL', 'inhibitPolicyMapping1 P12 CA CRL'])
    .WithCerts(['inhibitPolicyMapping1 P12 subsubCA Cert', 'inhibitPolicyMapping1 P12 subCA Cert', 'inhibitPolicyMapping1 P12 CA Cert']));
end;

procedure TNistCertPathTest.Test4_11_5;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitPolicyMapping Test5 EE')
    .WithCrls(['inhibitPolicyMapping5subsubsubCA CRL', 'inhibitPolicyMapping5 subsubCA CRL', 'inhibitPolicyMapping5 subCA CRL', 'inhibitPolicyMapping5 CA CRL'])
    .WithCerts(['inhibitPolicyMapping5 subsubsubCA Cert', 'inhibitPolicyMapping5 subsubCA Cert', 'inhibitPolicyMapping5 subCA Cert', 'inhibitPolicyMapping5 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_11_6;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitPolicyMapping Test6 EE')
    .WithCrls(['inhibitPolicyMapping1 P12subsubCAIPM5 CRL', 'inhibitPolicyMapping1 P12subCAIPM5 CRL', 'inhibitPolicyMapping1 P12 CA CRL'])
    .WithCerts(['inhibitPolicyMapping1 P12 subsubCAIPM5 Cert', 'inhibitPolicyMapping1 P12 subCAIPM5 Cert', 'inhibitPolicyMapping1 P12 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_11_7;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid SelfIssued inhibitPolicyMapping Test7 EE')
    .WithCrls(['inhibitPolicyMapping1 P1 subCA CRL', 'inhibitPolicyMapping1 P1 CA CRL'])
    .WithCerts(['inhibitPolicyMapping1 P1 subCA Cert', 'inhibitPolicyMapping1 P1 SelfIssued CA Cert', 'inhibitPolicyMapping1 P1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_11_8;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued inhibitPolicyMapping Test8 EE')
    .WithCrls(['inhibitPolicyMapping1 P1 subsubCACRL', 'inhibitPolicyMapping1 P1 subCA CRL', 'inhibitPolicyMapping1 P1 CA CRL'])
    .WithCerts(['inhibitPolicyMapping1 P1 subsubCA Cert', 'inhibitPolicyMapping1 P1 subCA Cert', 'inhibitPolicyMapping1 P1 SelfIssued CA Cert', 'inhibitPolicyMapping1 P1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_11_9;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued inhibitPolicyMapping Test9 EE')
    .WithCrls(['inhibitPolicyMapping1 P1 subsubCACRL', 'inhibitPolicyMapping1 P1 subCA CRL', 'inhibitPolicyMapping1 P1 CA CRL'])
    .WithCerts(['inhibitPolicyMapping1 P1 subsubCA Cert', 'inhibitPolicyMapping1 P1 subCA Cert', 'inhibitPolicyMapping1 P1 SelfIssued CA Cert', 'inhibitPolicyMapping1 P1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_11_10;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued inhibitPolicyMapping Test10 EE')
    .WithCerts(['inhibitPolicyMapping1 P1 SelfIssued subCA Cert', 'inhibitPolicyMapping1 P1 subCA Cert', 'inhibitPolicyMapping1 P1 SelfIssued CA Cert', 'inhibitPolicyMapping1 P1 CA Cert'])
    .WithCrls(['inhibitPolicyMapping1 P1 subCA CRL', 'inhibitPolicyMapping1 P1 CA CRL']), 0);
end;

procedure TNistCertPathTest.Test4_11_11;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued inhibitPolicyMapping Test11 EE')
    .WithCerts(['inhibitPolicyMapping1 P1 SelfIssued subCA Cert', 'inhibitPolicyMapping1 P1 subCA Cert', 'inhibitPolicyMapping1 P1 SelfIssued CA Cert', 'inhibitPolicyMapping1 P1 CA Cert'])
    .WithCrls(['inhibitPolicyMapping1 P1 subCA CRL', 'inhibitPolicyMapping1 P1 CA CRL']), 0);
end;

procedure TNistCertPathTest.Test4_12_1;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitAnyPolicy Test1 EE')
    .WithCrls(['inhibitAnyPolicy0 CA CRL'])
    .WithCerts(['inhibitAnyPolicy0 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_12_2;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid inhibitAnyPolicy Test2 EE')
    .WithCrls(['inhibitAnyPolicy0 CA CRL'])
    .WithCerts(['inhibitAnyPolicy0 CA Cert']));
end;

procedure TNistCertPathTest.Test4_12_3;
begin
  CheckAccepted(NewTest().WithEndEntity('inhibitAnyPolicy Test3 EE')
    .WithCrls(['inhibitAnyPolicy1 subCA1 CRL', 'inhibitAnyPolicy1 CA CRL'])
    .WithCerts(['inhibitAnyPolicy1 subCA1 Cert', 'inhibitAnyPolicy1 CA Cert']));
  CheckRejected(NewTest().WithEndEntity('inhibitAnyPolicy Test3 EE')
    .WithCrls(['inhibitAnyPolicy1 subCA1 CRL', 'inhibitAnyPolicy1 CA CRL'])
    .WithCerts(['inhibitAnyPolicy1 subCA1 Cert', 'inhibitAnyPolicy1 CA Cert'])
    .WithInhibitAnyPolicy(True), 1);
end;

procedure TNistCertPathTest.Test4_12_4;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitAnyPolicy Test4 EE')
    .WithCrls(['inhibitAnyPolicy1 subCA1 CRL', 'inhibitAnyPolicy1 CA CRL'])
    .WithCerts(['inhibitAnyPolicy1 subCA1 Cert', 'inhibitAnyPolicy1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_12_5;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitAnyPolicy Test5 EE')
    .WithCrls(['inhibitAnyPolicy5 subsubCA CRL', 'inhibitAnyPolicy5 subCA CRL', 'inhibitAnyPolicy5 CA CRL'])
    .WithCerts(['inhibitAnyPolicy5 subsubCA Cert', 'inhibitAnyPolicy5 subCA Cert', 'inhibitAnyPolicy5 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_12_6;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid inhibitAnyPolicy Test6 EE')
    .WithCrls(['inhibitAnyPolicy1 subCAIAP5 CRL', 'inhibitAnyPolicy1 CA CRL'])
    .WithCerts(['inhibitAnyPolicy1 subCAIAP5 Cert', 'inhibitAnyPolicy1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_12_7;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid SelfIssued inhibitAnyPolicy Test7 EE')
    .WithCrls(['inhibitAnyPolicy1 subCA2 CRL', 'inhibitAnyPolicy1 CA CRL'])
    .WithCerts(['inhibitAnyPolicy1 subCA2 Cert', 'inhibitAnyPolicy1 SelfIssued CA Cert', 'inhibitAnyPolicy1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_12_8;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued inhibitAnyPolicy Test8 EE')
    .WithCrls(['inhibitAnyPolicy1 subsubCA2 CRL', 'inhibitAnyPolicy1 subCA2 CRL', 'inhibitAnyPolicy1 CA CRL'])
    .WithCerts(['inhibitAnyPolicy1 subsubCA2 Cert', 'inhibitAnyPolicy1 subCA2 Cert', 'inhibitAnyPolicy1 SelfIssued CA Cert', 'inhibitAnyPolicy1 CA Cert']), 1);
end;

procedure TNistCertPathTest.Test4_12_9;
begin
  CheckAccepted(NewTest().WithPoliciesByName(['NIST-test-policy-1'])
    .WithEndEntity('Valid SelfIssued inhibitAnyPolicy Test9 EE')
    .WithCerts(['inhibitAnyPolicy1 SelfIssued subCA2 Cert', 'inhibitAnyPolicy1 subCA2 Cert', 'inhibitAnyPolicy1 SelfIssued CA Cert', 'inhibitAnyPolicy1 CA Cert'])
    .WithCrls(['inhibitAnyPolicy1 subCA2 CRL', 'inhibitAnyPolicy1 CA CRL']));
end;

procedure TNistCertPathTest.Test4_12_10;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid SelfIssued inhibitAnyPolicy Test10 EE')
    .WithCrls(['inhibitAnyPolicy1 subCA2 CRL', 'inhibitAnyPolicy1 CA CRL'])
    .WithCerts(['inhibitAnyPolicy1 subCA2 Cert', 'inhibitAnyPolicy1 SelfIssued CA Cert', 'inhibitAnyPolicy1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_1;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test1 EE')
    .WithCrls(['nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test2 EE')
    .WithCrls(['nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_3;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test3 EE')
    .WithCrls(['nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_4;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test4 EE')
    .WithCrls(['nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_5;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test5 EE')
    .WithCrls(['nameConstraints DN2 CA CRL'])
    .WithCerts(['nameConstraints DN2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_6;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test6 EE')
    .WithCrls(['nameConstraints DN3 CA CRL'])
    .WithCerts(['nameConstraints DN3 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_7;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test7 EE')
    .WithCrls(['nameConstraints DN3 CA CRL'])
    .WithCerts(['nameConstraints DN3 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_8;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test8 EE')
    .WithCrls(['nameConstraints DN4 CA CRL'])
    .WithCerts(['nameConstraints DN4 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_9;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test9 EE')
    .WithCrls(['nameConstraints DN4 CA CRL'])
    .WithCerts(['nameConstraints DN4 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_10;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test10 EE')
    .WithCrls(['nameConstraints DN5 CA CRL'])
    .WithCerts(['nameConstraints DN5 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_11;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test11 EE')
    .WithCrls(['nameConstraints DN5 CA CRL'])
    .WithCerts(['nameConstraints DN5 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_12;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test12 EE')
    .WithCrls(['nameConstraints DN1 subCA1 CRL', 'nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 subCA1 Cert', 'nameConstraints DN1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_13;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test13 EE')
    .WithCrls(['nameConstraints DN1 subCA2 CRL', 'nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 subCA2 Cert', 'nameConstraints DN1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_14;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test14 EE')
    .WithCrls(['nameConstraints DN1 subCA2 CRL', 'nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 subCA2 Cert', 'nameConstraints DN1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_15;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test15 EE')
    .WithCrls(['nameConstraints DN3 subCA1 CRL', 'nameConstraints DN3 CA CRL'])
    .WithCerts(['nameConstraints DN3 subCA1 Cert', 'nameConstraints DN3 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_16;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test16 EE')
    .WithCrls(['nameConstraints DN3 subCA1 CRL', 'nameConstraints DN3 CA CRL'])
    .WithCerts(['nameConstraints DN3 subCA1 Cert', 'nameConstraints DN3 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_17;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test17 EE')
    .WithCrls(['nameConstraints DN3 subCA2 CRL', 'nameConstraints DN3 CA CRL'])
    .WithCerts(['nameConstraints DN3 subCA2 Cert', 'nameConstraints DN3 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_18;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test18 EE')
    .WithCrls(['nameConstraints DN3 subCA2 CRL', 'nameConstraints DN3 CA CRL'])
    .WithCerts(['nameConstraints DN3 subCA2 Cert', 'nameConstraints DN3 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_19;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DN nameConstraints Test19 EE')
    .WithCerts(['nameConstraints DN1 SelfIssued CA Cert', 'nameConstraints DN1 CA Cert'])
    .WithCrls(['nameConstraints DN1 CA CRL']));
end;

procedure TNistCertPathTest.Test4_13_20;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DN nameConstraints Test20 EE')
    .WithCrls(['nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_21;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid RFC822 nameConstraints Test21 EE')
    .WithCrls(['nameConstraints RFC822 CA1 CRL'])
    .WithCerts(['nameConstraints RFC822 CA1 Cert']));
end;

procedure TNistCertPathTest.Test4_13_22;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid RFC822 nameConstraints Test22 EE')
    .WithCrls(['nameConstraints RFC822 CA1 CRL'])
    .WithCerts(['nameConstraints RFC822 CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_23;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid RFC822 nameConstraints Test23 EE')
    .WithCrls(['nameConstraints RFC822 CA2 CRL'])
    .WithCerts(['nameConstraints RFC822 CA2 Cert']));
end;

procedure TNistCertPathTest.Test4_13_24;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid RFC822 nameConstraints Test24 EE')
    .WithCrls(['nameConstraints RFC822 CA2 CRL'])
    .WithCerts(['nameConstraints RFC822 CA2 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_25;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid RFC822 nameConstraints Test25 EE')
    .WithCrls(['nameConstraints RFC822 CA3 CRL'])
    .WithCerts(['nameConstraints RFC822 CA3 Cert']));
end;

procedure TNistCertPathTest.Test4_13_26;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid RFC822 nameConstraints Test26 EE')
    .WithCrls(['nameConstraints RFC822 CA3 CRL'])
    .WithCerts(['nameConstraints RFC822 CA3 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_27;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid DN and RFC822 nameConstraints Test27 EE')
    .WithCrls(['nameConstraints DN1 subCA3 CRL', 'nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 subCA3 Cert', 'nameConstraints DN1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_28;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid DN and RFC822 nameConstraints Test28 EE')
    .WithCrls(['nameConstraints DN1 subCA3 CRL', 'nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 subCA3 Cert', 'nameConstraints DN1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_29;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid DN and RFC822 nameConstraints Test29 EE')
    .WithCrls(['nameConstraints DN1 subCA3 CRL', 'nameConstraints DN1 CA CRL'])
    .WithCerts(['nameConstraints DN1 subCA3 Cert', 'nameConstraints DN1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_30;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DNS nameConstraints Test30 EE')
    .WithCrls(['nameConstraints DNS1 CA CRL'])
    .WithCerts(['nameConstraints DNS1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_31;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DNS nameConstraints Test31 EE')
    .WithCrls(['nameConstraints DNS1 CA CRL'])
    .WithCerts(['nameConstraints DNS1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_32;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid DNS nameConstraints Test32 EE')
    .WithCrls(['nameConstraints DNS2 CA CRL'])
    .WithCerts(['nameConstraints DNS2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_33;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DNS nameConstraints Test33 EE')
    .WithCrls(['nameConstraints DNS2 CA CRL'])
    .WithCerts(['nameConstraints DNS2 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_34;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid URI nameConstraints Test34 EE')
    .WithCrls(['nameConstraints URI1 CA CRL'])
    .WithCerts(['nameConstraints URI1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_35;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid URI nameConstraints Test35 EE')
    .WithCrls(['nameConstraints URI1 CA CRL'])
    .WithCerts(['nameConstraints URI1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_36;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid URI nameConstraints Test36 EE')
    .WithCrls(['nameConstraints URI2 CA CRL'])
    .WithCerts(['nameConstraints URI2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_13_37;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid URI nameConstraints Test37 EE')
    .WithCrls(['nameConstraints URI2 CA CRL'])
    .WithCerts(['nameConstraints URI2 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_13_38;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid DNS nameConstraints Test38 EE')
    .WithCrls(['nameConstraints DNS1 CA CRL'])
    .WithCerts(['nameConstraints DNS1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_1;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid distributionPoint Test1 EE')
    .WithCrls(['distributionPoint1 CA CRL'])
    .WithCerts(['distributionPoint1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_14_2;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid distributionPoint Test2 EE')
    .WithCrls(['distributionPoint1 CA CRL'])
    .WithCerts(['distributionPoint1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_3;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid distributionPoint Test3 EE')
    .WithCrls(['distributionPoint1 CA CRL'])
    .WithCerts(['distributionPoint1 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_4;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid distributionPoint Test4 EE')
    .WithCrls(['distributionPoint1 CA CRL'])
    .WithCerts(['distributionPoint1 CA Cert']));
end;

procedure TNistCertPathTest.Test4_14_5;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid distributionPoint Test5 EE')
    .WithCrls(['distributionPoint2 CA CRL'])
    .WithCerts(['distributionPoint2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_14_6;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid distributionPoint Test6 EE')
    .WithCrls(['distributionPoint2 CA CRL'])
    .WithCerts(['distributionPoint2 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_7;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid distributionPoint Test7 EE')
    .WithCrls(['distributionPoint2 CA CRL'])
    .WithCerts(['distributionPoint2 CA Cert']));
end;

procedure TNistCertPathTest.Test4_14_8;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid distributionPoint Test8 EE')
    .WithCrls(['distributionPoint2 CA CRL'])
    .WithCerts(['distributionPoint2 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_9;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid distributionPoint Test9 EE')
    .WithCrls(['distributionPoint2 CA CRL'])
    .WithCerts(['distributionPoint2 CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_10;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid No issuingDistributionPoint Test10 EE')
    .WithCrls(['No issuingDistributionPoint CA CRL'])
    .WithCerts(['No issuingDistributionPoint CA Cert']));
end;

procedure TNistCertPathTest.Test4_14_11;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid onlyContainsUserCerts Test11 EE')
    .WithCrls(['onlyContainsUserCerts CA CRL'])
    .WithCerts(['onlyContainsUserCerts CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_12;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid onlyContainsCACerts Test12 EE')
    .WithCrls(['onlyContainsCACerts CA CRL'])
    .WithCerts(['onlyContainsCACerts CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_13;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid onlyContainsCACerts Test13 EE')
    .WithCrls(['onlyContainsCACerts CA CRL'])
    .WithCerts(['onlyContainsCACerts CA Cert']));
end;

procedure TNistCertPathTest.Test4_14_14;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid onlyContainsAttributeCerts Test14 EE')
    .WithCrls(['onlyContainsAttributeCerts CA CRL'])
    .WithCerts(['onlyContainsAttributeCerts CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_15;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid onlySomeReasons Test15 EE')
    .WithCrls(['onlySomeReasons CA1 other reasons CRL', 'onlySomeReasons CA1 compromise CRL'])
    .WithCerts(['onlySomeReasons CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_16;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid onlySomeReasons Test16 EE')
    .WithCrls(['onlySomeReasons CA1 other reasons CRL', 'onlySomeReasons CA1 compromise CRL'])
    .WithCerts(['onlySomeReasons CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_17;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid onlySomeReasons Test17 EE')
    .WithCrls(['onlySomeReasonsCA2 CRL2', 'onlySomeReasons CA2 CRL1'])
    .WithCerts(['onlySomeReasons CA2 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_18;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid onlySomeReasons Test18 EE')
    .WithCrls(['onlySomeReasons CA3 other reasons CRL', 'onlySomeReasons CA3 compromise CRL'])
    .WithCerts(['onlySomeReasons CA3 Cert']));
end;

procedure TNistCertPathTest.Test4_14_19;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid onlySomeReasons Test19 EE')
    .WithCrls(['onlySomeReasons CA4 other reasons CRL', 'onlySomeReasons CA4 compromise CRL'])
    .WithCerts(['onlySomeReasons CA4 Cert']));
end;

procedure TNistCertPathTest.Test4_14_20;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid onlySomeReasons Test20 EE')
    .WithCrls(['onlySomeReasons CA4 other reasons CRL', 'onlySomeReasons CA4 compromise CRL'])
    .WithCerts(['onlySomeReasons CA4 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_21;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid onlySomeReasons Test21 EE')
    .WithCrls(['onlySomeReasons CA4 other reasons CRL', 'onlySomeReasons CA4 compromise CRL'])
    .WithCerts(['onlySomeReasons CA4 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_22;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid IDP with indirectCRL Test22 EE')
    .WithCrls(['indirectCRL CA1 CRL']).WithCerts(['indirectCRL CA1 Cert']));
end;

procedure TNistCertPathTest.Test4_14_23;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid IDP with indirectCRL Test23 EE')
    .WithCrls(['indirectCRL CA1 CRL']).WithCerts(['indirectCRL CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_24;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid IDP with indirectCRL Test24 EE')
    .WithCrls(['indirectCRL CA1 CRL']).WithCerts(['indirectCRL CA2 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA1 Cert']));
end;

procedure TNistCertPathTest.Test4_14_25;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid IDP with indirectCRL Test25 EE')
    .WithCrls(['indirectCRL CA1 CRL']).WithCerts(['indirectCRL CA2 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA1 Cert']));
end;

procedure TNistCertPathTest.Test4_14_26;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid IDP with indirectCRL Test26 EE')
    .WithCrls(['indirectCRL CA1 CRL']).WithCerts(['indirectCRL CA2 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_27;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid cRLIssuer Test27 EE')
    .WithCrls(['Good CA CRL']).WithCerts(['indirectCRL CA2 Cert'])
    .WithCrlSignerCerts(['Good CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_28;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid cRLIssuer Test28 EE')
    .WithCrls(['indirectCRL CA3 cRLIssuer CRL', 'indirectCRL CA3 CRL'])
    .WithCerts(['indirectCRL CA3 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA3 cRLIssuer Cert']));
end;

procedure TNistCertPathTest.Test4_14_29;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid cRLIssuer Test29 EE')
    .WithCrls(['indirectCRL CA3 cRLIssuer CRL', 'indirectCRL CA3 CRL'])
    .WithCerts(['indirectCRL CA3 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA3 cRLIssuer Cert']));
end;

procedure TNistCertPathTest.Test4_14_30;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid cRLIssuer Test30 EE')
    .WithCrls(['indirectCRL CA4 cRLIssuer CRL'])
    .WithCerts(['indirectCRL CA4 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA4 cRLIssuer Cert']));
end;

procedure TNistCertPathTest.Test4_14_31;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid cRLIssuer Test31 EE')
    .WithCerts(['indirectCRL CA6 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA5 Cert'])
    .WithCrls(['indirectCRL CA5 CRL']), 0);
end;

procedure TNistCertPathTest.Test4_14_32;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid cRLIssuer Test32 EE')
    .WithCerts(['indirectCRL CA6 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA5 Cert'])
    .WithCrls(['indirectCRL CA5 CRL']), 0);
end;

procedure TNistCertPathTest.Test4_14_33;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid cRLIssuer Test33 EE')
    .WithCerts(['indirectCRL CA6 Cert'])
    .WithCrlSignerCerts(['indirectCRL CA5 Cert'])
    .WithCrls(['indirectCRL CA5 CRL']));
end;

procedure TNistCertPathTest.Test4_14_34;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid cRLIssuer Test34 EE')
    .WithCrls(['indirectCRL CA5 CRL']).WithCerts(['indirectCRL CA5 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_14_35;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid cRLIssuer Test35 EE')
    .WithCrls(['indirectCRL CA5 CRL']).WithCerts(['indirectCRL CA5 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_15_1;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid deltaCRLIndicator No Base Test1 EE')
    .WithCrls(['deltaCRLIndicator No Base CA CRL'])
    .WithCerts(['deltaCRLIndicator No Base CA Cert']), 0);
end;

procedure TNistCertPathTest.Test4_15_2;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid deltaCRL Test2 EE')
    .WithCrls(['deltaCRL CA1 deltaCRL', 'deltaCRL CA1 CRL'])
    .WithCerts(['deltaCRL CA1 Cert']));
end;

procedure TNistCertPathTest.Test4_15_3;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid deltaCRL Test3 EE')
    .WithCrls(['deltaCRL CA1 deltaCRL', 'deltaCRL CA1 CRL'])
    .WithCerts(['deltaCRL CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_15_4;
begin
  CheckRejected(NewTest().EnableDeltaCrls(True)
    .WithEndEntity('Invalid deltaCRL Test4 EE')
    .WithCrls(['deltaCRL CA1 deltaCRL', 'deltaCRL CA1 CRL'])
    .WithCerts(['deltaCRL CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_15_5;
begin
  CheckAccepted(NewTest().EnableDeltaCrls(True)
    .WithEndEntity('Valid deltaCRL Test5 EE')
    .WithCrls(['deltaCRL CA1 deltaCRL', 'deltaCRL CA1 CRL'])
    .WithCerts(['deltaCRL CA1 Cert']));
end;

procedure TNistCertPathTest.Test4_15_6;
begin
  CheckRejected(NewTest().EnableDeltaCrls(True)
    .WithEndEntity('Invalid deltaCRL Test6 EE')
    .WithCrls(['deltaCRL CA1 deltaCRL', 'deltaCRL CA1 CRL'])
    .WithCerts(['deltaCRL CA1 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_15_7;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid deltaCRL Test7 EE')
    .WithCrls(['deltaCRL CA1 deltaCRL', 'deltaCRL CA1 CRL'])
    .WithCerts(['deltaCRL CA1 Cert']));
end;

procedure TNistCertPathTest.Test4_15_8;
begin
  CheckAccepted(NewTest().WithEndEntity('Valid deltaCRL Test8 EE')
    .WithCrls(['deltaCRL CA2 deltaCRL', 'deltaCRL CA2 CRL'])
    .WithCerts(['deltaCRL CA2 Cert']));
end;

procedure TNistCertPathTest.Test4_15_9;
begin
  CheckRejected(NewTest().WithEndEntity('Invalid deltaCRL Test9 EE')
    .WithCrls(['deltaCRL CA2 deltaCRL', 'deltaCRL CA2 CRL'])
    .WithCerts(['deltaCRL CA2 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_15_10;
begin
  CheckRejected(NewTest().EnableDeltaCrls(True)
    .WithEndEntity('Invalid deltaCRL Test10 EE')
    .WithCrls(['deltaCRL CA3 deltaCRL', 'deltaCRL CA3 CRL'])
    .WithCerts(['deltaCRL CA3 Cert']), 0);
end;

procedure TNistCertPathTest.Test4_16_1;
begin
  CheckAccepted(NewTest()
    .WithEndEntity('Valid Unknown Not Critical Certificate Extension Test1 EE'));
end;

procedure TNistCertPathTest.Test4_16_2;
begin
  CheckRejected(NewTest()
    .WithEndEntity('Invalid Unknown Critical Certificate Extension Test2 EE'), 0);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TNistCertPathTest);
{$ELSE}
  RegisterTest(TNistCertPathTest.Suite);
{$ENDIF FPC}

end.
