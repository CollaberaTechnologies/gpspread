//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace WebApplication6.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class HCM_STATES
    {
        public long RID { get; set; }
        public string Title { get; set; }
        public long CountryID { get; set; }
        public string StateCode { get; set; }
        public short LanguageType { get; set; }
        public long EngKeyID { get; set; }
        public long CreatedUserID { get; set; }
        public System.DateTime CreatedDate { get; set; }
        public Nullable<long> ModifiedUserID { get; set; }
        public Nullable<System.DateTime> ModifiedDate { get; set; }
        public string RefID { get; set; }
        public bool Status { get; set; }
        public Nullable<System.DateTime> EffectiveDate { get; set; }
        public long TID { get; set; }
        public long V4RID { get; set; }
    }
}
